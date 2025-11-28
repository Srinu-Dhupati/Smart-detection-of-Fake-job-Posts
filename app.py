from flask import Flask, render_template, request, redirect, flash, session, url_for
from werkzeug.utils import secure_filename
import os
import gc
from database import register_user, get_user, init_db
from functools import wraps
import torch
from transformers import AlbertTokenizer, AlbertModel
import joblib
import numpy as np
import logging
import cv2
from PIL import Image
import pytesseract
import re
import string
from scam_detector import ScamDetector
import shap
import matplotlib.pyplot as plt
import base64
from io import BytesIO

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure folders and limits
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configure Tesseract path
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Create uploads folder and initialize database
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
init_db()

class JobPostAnalyzer:
    def __init__(self):
        try:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.tokenizer = AlbertTokenizer.from_pretrained('albert-base-v2')
            self.albert_model = AlbertModel.from_pretrained('albert-base-v2').to(self.device)
            self.albert_model.eval()
            self.xgb_model = joblib.load("models/model.pkl")
            self.scam_detector = ScamDetector()
            self.explainer = shap.TreeExplainer(self.xgb_model)
            logger.info("All components loaded successfully")
        except Exception as e:
            logger.error(f"Initialization error: {e}")
            raise

    def get_albert_embeddings(self, text):
        try:
            inputs = self.tokenizer(
                text,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.albert_model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
            return embeddings
        except Exception as e:
            logger.error(f"Error generating embeddings: {e}")
            raise

    def extract_text_from_image(self, image_path):
        try:
            pil_image = Image.open(image_path)
            if pil_image.mode != 'RGB':
                pil_image = pil_image.convert('RGB')
            image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            if image is None:
                raise ValueError("Failed to load image")

            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            denoised = cv2.fastNlMeansDenoising(gray)
            
            versions = [
                gray,
                denoised,
                cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
                cv2.adaptiveThreshold(denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2),
                cv2.GaussianBlur(denoised, (3, 3), 0),
                cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)[1],
                cv2.medianBlur(gray, 3)
            ]

            all_texts = []
            for img_version in versions:
                try:
                    for psm in ['6', '3', '4']:
                        custom_config = f'--oem 3 --psm {psm}'
                        text = pytesseract.image_to_string(img_version, config=custom_config)
                        if text and text.strip():
                            all_texts.append(text.strip())
                except Exception as e:
                    logger.warning(f"OCR failed for image version: {str(e)}")
                    continue

            if not all_texts:
                return "No text could be extracted from the image"

            combined_text = " ".join(all_texts)
            cleaned_text = " ".join(combined_text.split())
            
            if len(cleaned_text.strip()) < 10:
                return "Extracted text is too short or unclear"
            
            return cleaned_text

        except Exception as e:
            logger.error(f"OCR Error: {str(e)}")
            return "Error occurred while processing the image"

    def analyze_job_post(self, text):
        try:
            if not text or not isinstance(text, str):
                return {
                    'result': 'ERROR',
                    'confidence': 0.0,
                    'explanation': 'Invalid or empty text provided.'
                }
            
            text = text.strip()
            if len(text) < 10:
                return {
                    'result': 'ERROR',
                    'confidence': 0.0,
                    'explanation': 'Text is too short for analysis.'
                }

            template_indicators = [
                r'\[.*?\]',
                'template.net',
                'letter template',
                'cover letter is a',
                'writing a cover letter',
                'your company name',
                'your name',
                'your email',
                'company name',
                'position title',
                'job title',
                'your address',
                'your phone',
                'your signature',
                'read your draft',
                'example template',
                'sample letter',
                'bullet points and include',
                'provide examples of'
            ]
            
            placeholder_pattern = re.compile(r'\[.*?\]|\{.*?\}|\<.*?\>')
            placeholders_found = placeholder_pattern.findall(text.lower())
            
            template_matches = []
            for indicator in template_indicators:
                if indicator.lower() in text.lower():
                    template_matches.append(indicator)
            
            if placeholders_found or template_matches:
                template_flags = []
                if placeholders_found:
                    template_flags.extend([f"Placeholder found: {p}" for p in placeholders_found])
                if template_matches:
                    template_flags.extend([f"Template indicator: {m}" for m in template_matches])
                
                return {
                    'result': 'FAKE',
                    'confidence': 0.95,
                    'flags_found': ['Template Document Detected'] + template_flags,
                    'flag_details': {
                        'placeholders': placeholders_found,
                        'template_indicators': template_matches
                    },
                    'legitimate_indicators': [],
                    'legitimate_details': {},
                    'suspicious_score': 0.95,
                    'legitimate_score': 0.05,
                    'shap_plot': None,
                    'ml_prediction': 'FAKE',
                    'ml_confidence': 0.95,
                    'rule_based_score': 0.95,
                    'explanation': f'This appears to be a template document with {len(placeholders_found)} placeholders and {len(template_matches)} template indicators found.'
                }

            rule_analysis = self.scam_detector.check_text(text)
            if not rule_analysis:
                rule_analysis = {'flags_found': [], 'legitimate_indicators': [], 'suspicious_score': 0}
            
            embeddings = self.get_albert_embeddings([text])
            scam_features = self.scam_detector.extract_features(text)
            
            if scam_features is None:
                return {
                    'result': 'ERROR',
                    'confidence': 0.0,
                    'explanation': 'Feature extraction failed.'
                }
            
            prediction = self.xgb_model.predict(embeddings)[0]
            probabilities = self.xgb_model.predict_proba(embeddings)[0]
            
            ml_score = float(probabilities[1])
            rule_score = float(rule_analysis.get('suspicious_score', 0))
            num_suspicious = len(rule_analysis.get('flags_found', []))
            num_legitimate = len(rule_analysis.get('legitimate_indicators', []))
            
            pattern_weight = min(0.25 * num_suspicious, 0.7)
            
            suspicious_phrases = [
                'profile caught my eye',
                'look forward to discussing',
                'working together',
                'excited about possibly',
                'immediate start',
                'urgent position',
                'work from home opportunity',
                'no experience necessary',
                'unlimited earning potential'
            ]
            suspicious_phrases_penalty = 0.15 if any(phrase in text.lower() for phrase in suspicious_phrases) else 0
            
            combined_score = (0.2 * ml_score) + (0.4 * rule_score) + pattern_weight + suspicious_phrases_penalty
            combined_score = min(max(combined_score, 0.0), 1.0)
            
            is_fake = (
                combined_score > 0.35 or
                num_suspicious >= 2 or
                (num_suspicious > 0 and num_legitimate == 0) or
                suspicious_phrases_penalty > 0
            )
            
            try:
                shap_values = self.explainer.shap_values(embeddings)
                plt.figure()
                shap.summary_plot(shap_values, embeddings, show=False)
                buf = BytesIO()
                plt.savefig(buf, format='png', bbox_inches='tight')
                plt.close()
                buf.seek(0)
                shap_plot = base64.b64encode(buf.getvalue()).decode('utf-8')
            except Exception as e:
                logger.error(f"SHAP plot generation failed: {e}")
                shap_plot = None
            
            return {
                'result': 'FAKE' if is_fake else 'REAL',
                'confidence': float(combined_score),
                'flags_found': rule_analysis.get('flags_found', []),
                'flag_details': rule_analysis.get('flag_details', {}),
                'legitimate_indicators': rule_analysis.get('legitimate_indicators', []),
                'legitimate_details': rule_analysis.get('legitimate_details', {}),
                'suspicious_score': combined_score,
                'legitimate_score': 1 - combined_score,
                'shap_plot': shap_plot,
                'ml_prediction': 'FAKE' if prediction else 'REAL',
                'ml_confidence': float(max(probabilities)),
                'rule_based_score': rule_score,
                'explanation': self._generate_explanation(is_fake, combined_score, rule_analysis)
            }
            
        except Exception as e:
            logger.error(f"ML analysis failed: {str(e)}", exc_info=True)
            return {
                'result': 'ERROR',
                'confidence': 0.0,
                'explanation': f'Analysis failed: {str(e)}.'
            }

    def _generate_explanation(self, is_fake, confidence, rule_analysis):
        result = "fraudulent" if is_fake else "legitimate"
        explanation = [f"This job posting appears to be {result} with {confidence:.1%} confidence."]
        
        if rule_analysis and rule_analysis.get('flags_found'):
            explanation.append(f"Found {len(rule_analysis['flags_found'])} suspicious indicators:")
            explanation.extend([f"- {flag}" for flag in rule_analysis['flags_found']])
        
        if rule_analysis and rule_analysis.get('legitimate_indicators'):
            explanation.append(f"Found {len(rule_analysis['legitimate_indicators'])} legitimate indicators:")
            explanation.extend([f"- {ind}" for ind in rule_analysis['legitimate_indicators']])
        
        return " ".join(explanation)

def clear_memory():
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

try:
    analyzer = JobPostAnalyzer()
except Exception as e:
    logger.error(f"Failed to initialize JobPostAnalyzer: {e}")
    raise SystemExit("Failed to initialize required components")




# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('predict'))
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('predict'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not all([username, email, password, confirm_password]):
                flash("All fields are required!", "danger")
                return render_template('register.html')

            if len(password) < 6:
                flash("Password must be at least 6 characters long!", "danger")
                return render_template('register.html')

            if password != confirm_password:
                flash("Passwords do not match!", "danger")
                return render_template('register.html')

            if register_user(username, password, email):
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("Username or email already exists!", "danger")
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash("An error occurred during registration.", "danger")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('predict'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                flash("Please enter both username and password!", "danger")
                return render_template('login.html')

            user = get_user(username, password)
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                flash("Login successful!", "success")
                return redirect(url_for('predict'))
            else:
                flash("Invalid username or password!", "danger")
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash("An error occurred during login.", "danger")

    return render_template('login.html')

@app.route("/predict", methods=["GET", "POST"])
@login_required
def predict():
    if request.method == "POST":
        try:
            clear_memory()
            
            job_description = request.form.get("job_description", "").strip()
            image = request.files.get("image")
            image_path = None

            if not job_description and not image:
                flash("Please provide either a job description or an image.", "warning")
                return render_template("prediction.html", username=session.get('username'))

            text_to_analyze = None
            extracted_text = None

            if job_description:
                text_to_analyze = job_description
            
            elif image and image.filename:
                if not allowed_file(image.filename):
                    flash("Invalid file type! Please upload an image file (PNG, JPG, JPEG).", "danger")
                    return render_template("prediction.html", username=session.get('username'))
                
                try:
                    filename = secure_filename(image.filename)
                    image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    image.save(image_path)

                    extracted_text = analyzer.extract_text_from_image(image_path)
                    
                    if extracted_text:
                        text_to_analyze = extracted_text
                    else:
                        flash("Could not extract text from image", "warning")
                        return render_template("prediction.html", username=session.get('username'))
                
                except Exception as e:
                    flash(f"Error processing image: {str(e)}", "danger")
                    logger.error(f"Image processing error: {str(e)}")
                    return render_template("prediction.html", username=session.get('username'))

            if text_to_analyze:
                try:
                    logger.info(f"Analyzing text (first 100 chars): {text_to_analyze[:100]}...")
                    
                    analysis = analyzer.analyze_job_post(text_to_analyze)
                    
                    if analysis.get('result') == 'ERROR':
                        flash(analysis['explanation'], "danger")
                        return render_template("prediction.html", username=session.get('username'))

                    analysis.update({
                        'extracted_text': extracted_text if image else None,
                        'input_text': job_description if job_description else None
                    })

                    return render_template(
                        "prediction.html",
                        **analysis,
                        username=session.get('username')
                    )

                except Exception as e:
                    logger.error(f"Analysis error: {str(e)}", exc_info=True)
                    flash(f"Error during analysis: {str(e)}", "danger")
            else:
                flash("No text to analyze", "warning")

        except Exception as e:
            logger.error(f"Prediction error: {str(e)}", exc_info=True)
            flash(f"An error occurred: {str(e)}", "danger")
        
        finally:
            if image_path and os.path.exists(image_path):
                try:
                    os.remove(image_path)
                except Exception as e:
                    logger.error(f"Failed to remove uploaded file: {e}")
            clear_memory()

    return render_template("prediction.html", username=session.get('username'))



@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(error):
    flash("File is too large! Maximum size is 16MB.", "danger")
    return redirect(url_for('predict'))

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=7860)

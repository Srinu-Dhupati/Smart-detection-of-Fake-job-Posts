import os
import pandas as pd
import numpy as np
import torch
import logging
import joblib
import shap
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.utils.class_weight import compute_class_weight
from imblearn.over_sampling import SMOTE
from transformers import AlbertTokenizer, AlbertModel
from xgboost import XGBClassifier
from scam_detector import ScamDetector
from multiprocessing import Pool, cpu_count

# Initialize tokenizer and device
tokenizer = AlbertTokenizer.from_pretrained('albert-base-v2')
device = "cuda" if torch.cuda.is_available() else "cpu"

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize ScamDetector
logger.info("Initializing ScamDetector...")
scam_detector = ScamDetector()

def get_albert_embeddings(texts, batch_size=16):
    """Generate ALBERT embeddings for texts"""
    try:
        embeddings = []
        total_batches = len(texts) // batch_size + (1 if len(texts) % batch_size != 0 else 0)
        
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            
            # Tokenize texts
            inputs = tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt"
            ).to(device)
            
            # Generate embeddings
            with torch.no_grad():
                outputs = albert_model(**inputs)
                batch_embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
                embeddings.extend(batch_embeddings)
            
            batch_num = (i // batch_size) + 1
            logger.info(f"Processed batch {batch_num}/{total_batches}")
        
        return np.array(embeddings)
    except Exception as e:
        logger.error(f"Error in generating embeddings: {e}")
        raise

def extract_scam_features(row):
    """Extract features using ScamDetector"""
    try:
        features = scam_detector.extract_features(row.get('job_description', ''))
        if features is None:
            logger.warning(f"No features extracted for text: {row.get('job_description', '')[:100]}...")
        return features
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return None

def train_model():
    try:
        # Load Dataset
        data_path = os.path.join(os.getcwd(), "dataset.csv")
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Dataset file not found at: {data_path}")
        
        logger.info("Loading dataset...")
        df = pd.read_csv(data_path, encoding='latin1')
        df = df.fillna("")
        logger.info(f"Dataset loaded successfully with {len(df)} samples")

        # Extract ScamDetector Features
        with Pool(cpu_count()) as p:
            logger.info(f"Using {cpu_count()} CPU cores for parallel processing")
            scam_features = p.map(extract_scam_features, [row for _, row in df.iterrows()])
        
        valid_features = [f for f in scam_features if f is not None]
        if len(valid_features) != len(df):
            logger.warning(f"Failed to extract features for {len(df) - len(valid_features)} samples")
        
        scam_features_df = pd.DataFrame(valid_features)
        logger.info(f"Extracted {len(scam_features_df.columns)} scam-related features")
        
        # Load ALBERT Model
        global albert_model
        albert_model = AlbertModel.from_pretrained("albert-base-v2").to(device)
        albert_model.eval()
        logger.info("ALBERT model loaded successfully")
        
        # Generate or Load ALBERT Embeddings
        embeddings_path = os.path.join(os.getcwd(), "albert_embeddings.npy")
        if not os.path.exists(embeddings_path):
            logger.info("Computing ALBERT embeddings...")
            X_embeddings = get_albert_embeddings(df["requirements"].tolist(), batch_size=16)
            np.save(embeddings_path, X_embeddings)
            logger.info(f"Embeddings saved to {embeddings_path}")
        else:
            logger.info("Loading precomputed ALBERT embeddings...")
            X_embeddings = np.load(embeddings_path)
        
        # Combine Features
        logger.info("Combining ALBERT embeddings with ScamDetector features...")
        X = np.hstack((X_embeddings, scam_features_df.values))
        y = df['fraudulent'].values
        logger.info(f"Final feature matrix shape: {X.shape}")
        
        # Apply SMOTE
        logger.info("Applying SMOTE for class balancing...")
        
        smote = SMOTE(random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)
        logger.info(f"After SMOTE - Samples: {len(y_resampled)}, Class distribution: {np.bincount(y_resampled)}")
        
        # Split Data
        X_train, X_test, y_train, y_test = train_test_split(
            X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled
        )
        
        # Train Model
        logger.info("Training XGBoost model...")
        model = XGBClassifier(
            learning_rate=0.1,
            max_depth=7,
            min_child_weight=1,
            subsample=0.8,
            colsample_bytree=0.8,
            n_estimators=200,
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss'
        )
        model.fit(
            X_train, 
            y_train,
            eval_set=[(X_test, y_test)],
          
            verbose=True
        )
        
        # Model Evaluation
        preds = model.predict(X_test)
        accuracy = metrics.accuracy_score(y_test, preds) * 100
        logger.info(f"Model Accuracy: {accuracy:.2f}%")
        logger.info("\nClassification Report:\n" + metrics.classification_report(y_test, preds))
        logger.info("\nConfusion Matrix:\n" + str(metrics.confusion_matrix(y_test, preds)))
        
        # SHAP Analysis
        logger.info("Computing SHAP values...")
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test)
        np.save("shap_values.npy", shap_values)
        logger.info("SHAP analysis completed and saved")
        
        # Save Model and Artifacts
        model_dir = os.path.join(os.getcwd(), "models")
        os.makedirs(model_dir, exist_ok=True)
        
        model_path = os.path.join(model_dir, "model.pkl")
        scam_detector_path = os.path.join(model_dir, "scam_detector.pkl")
        
        joblib.dump(model, model_path)
        joblib.dump(scam_detector, scam_detector_path)
        logger.info("Model and artifacts saved successfully")
        
        return {
            'model': model,
            'accuracy': accuracy,
            'shap_values': shap_values
        }
        
    except Exception as e:
        logger.error(f"Training pipeline failed: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        results = train_model()
        logger.info("Training pipeline completed successfully!")
    except Exception as e:
        logger.error(f"Main execution failed: {str(e)}")
        raise
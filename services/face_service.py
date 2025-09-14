import base64
import io
from PIL import Image  # Fixed: Changed from tkinter to PIL
import cv2
import face_recognition
import numpy as np
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
import logging
import insightface

from backend.database import FaceEncoding

class FaceDuplicateDetectionService:
    
    def __init__(self):
        self.similarity_threshold = 0.6  # Adjust based on your requirements
        self.logger = logging.getLogger(__name__)
        
        # Initialize the InsightFace app - this was missing!
        self.app = insightface.app.FaceAnalysis(providers=['CPUExecutionProvider'])
        self.app.prepare(ctx_id=0, det_size=(640, 640))

    def extract_face_encodings(self, image_data: str, angle_info: str = "center") -> tuple:
        """Extract face encoding from base64 image data"""
        try:
            # Decode base64 image
            img_data = base64.b64decode(image_data.split(',')[1] if ',' in image_data else image_data)
            img = Image.open(io.BytesIO(img_data))
            img_array = np.array(img)
            
            # Convert RGB to BGR for OpenCV
            if len(img_array.shape) == 3:
                img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            # Detect faces
            faces = self.app.get(img_array)
            
            if not faces:
                return None, f"No face detected in {angle_info} image"
            
            if len(faces) > 1:
                return None, f"Multiple faces detected in {angle_info} image. Please ensure only one face is visible."
            
            # Get the face with highest confidence
            face = faces[0]
            
            # Extract embedding (face encoding)
            embedding = face.embedding
            confidence = face.det_score
            
            return {
                'embedding': embedding,
                'confidence': confidence,
                'angle_info': angle_info,
                'bbox': face.bbox.tolist()
            }, None
            
        except Exception as e:
            return None, f"Error processing {angle_info} image: {str(e)}"
   
    def check_for_duplicate_registration(
        self, 
        new_face_encodings: List[np.ndarray], 
        new_email: str,
        db: Session
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if the face being registered already exists for a different email
        
        Args:
            new_face_encodings: Face encodings from registration images
            new_email: Email being used for registration
            db: Database session
            
        Returns:
            Tuple of (is_duplicate, existing_email)
        """
        if not new_face_encodings:
            return False, None
        
        # Import here to avoid circular imports
        
        # Get all existing face profiles except for the current email
        existing_profiles = db.query(FaceEncoding).filter(
            FaceEncoding.email != new_email
        ).all()

        
        for existing_enc in existing_profiles:
            try:
                # Deserialize stored face encoding
                stored_encoding = np.frombuffer(existing_enc.encoding, dtype=np.float32)
                
                # Compare with new encodings
                for new_encoding in new_face_encodings:
                    similarity = self.compare_encodings(new_encoding, stored_encoding)
                    
                    if similarity >= self.similarity_threshold:
                        return True, existing_enc.email
                        
            except Exception as e:
                self.logger.error(f"Error comparing with encoding {existing_enc.id}: {str(e)}")
                continue
        
        return False, None
    
    def compare_encodings(self, encoding1: np.ndarray, encoding2: np.ndarray) -> float:
        """Compare two face encodings and return similarity score"""
        # Calculate cosine similarity
        dot_product = np.dot(encoding1, encoding2)
        norm1 = np.linalg.norm(encoding1)
        norm2 = np.linalg.norm(encoding2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
            
        similarity = dot_product / (norm1 * norm2)
        return similarity

    def are_faces_similar(
        self, 
        encodings1: List[np.ndarray], 
        encodings2: List[np.ndarray]
    ) -> bool:
        """
        Compare two sets of face encodings to determine if they're from the same person
        
        Args:
            encodings1: First set of face encodings
            encodings2: Second set of face encodings
            
        Returns:
            True if faces are similar enough to be considered the same person
        """
        if not encodings1 or not encodings2:
            return False
        
        similarity_scores = []
        
        # Compare each encoding from set 1 with each from set 2
        for enc1 in encodings1:
            for enc2 in encodings2:
                # Calculate face distance (lower = more similar)
                distance = face_recognition.face_distance([enc2], enc1)[0]
                similarity = 1 - distance  # Convert to similarity score
                similarity_scores.append(similarity)
        
        # Use the highest similarity score
        max_similarity = max(similarity_scores) if similarity_scores else 0
        
        return max_similarity >= self.similarity_threshold
    
    def serialize_encodings(self, encodings: List[np.ndarray]) -> bytes:
        """Serialize face encodings for database storage"""
        return np.array(encodings).tobytes()
    
    def deserialize_encodings(self, encoded_data: bytes) -> List[np.ndarray]:
        """Deserialize face encodings from database"""
        # Assuming each encoding is 128 dimensions (face_recognition default)
        # For InsightFace, it's usually 512 dimensions
        arr = np.frombuffer(encoded_data, dtype=np.float64)
        return arr.reshape(-1, 512).tolist()  # Changed to 512 for InsightFace
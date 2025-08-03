"""
Biometric Verification Helper Methods

Advanced algorithms for face quality assessment, liveness detection,
anti-spoofing measures, and geometric analysis.
"""

import logging
import numpy as np
import cv2
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class BiometricHelpers:
    """Helper methods for advanced biometric verification"""
    
    @staticmethod
    async def assess_face_quality(image: np.ndarray) -> Dict[str, Any]:
        """
        Comprehensive face quality assessment for biometric recognition.
        
        Args:
            image: OpenCV image containing face
            
        Returns:
            Dict containing quality metrics and scores
        """
        try:
            # Convert to grayscale for analysis
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
            
            # 1. Sharpness Assessment (Laplacian variance)
            laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
            sharpness_score = min(laplacian_var / 1000.0, 1.0)
            
            # 2. Brightness Assessment
            brightness = np.mean(gray)
            brightness_score = 1.0 - abs(brightness - 128) / 128.0
            
            # 3. Contrast Assessment
            contrast = gray.std()
            contrast_score = min(contrast / 80.0, 1.0)
            
            # 4. Symmetry Assessment
            height, width = gray.shape
            left_half = gray[:, :width//2]
            right_half = cv2.flip(gray[:, width//2:], 1)
            
            # Resize to match if needed
            min_width = min(left_half.shape[1], right_half.shape[1])
            left_half = left_half[:, :min_width]
            right_half = right_half[:, :min_width]
            
            symmetry_correlation = np.corrcoef(left_half.flatten(), right_half.flatten())[0, 1]
            symmetry_score = max(0.0, symmetry_correlation)
            
            # 5. Eye Region Quality (if eyes detected)
            eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
            eyes = eye_cascade.detectMultiScale(gray, 1.1, 4)
            
            eye_quality_score = 1.0 if len(eyes) >= 2 else 0.5
            
            # 6. Pose Assessment (using facial landmarks if available)
            pose_score = BiometricHelpers._assess_head_pose(gray)
            
            # 7. Resolution Quality
            face_area = height * width
            resolution_score = min(face_area / (150 * 150), 1.0)  # Minimum 150x150 pixels
            
            # Weighted overall quality score
            quality_weights = {
                'sharpness': 0.25,
                'brightness': 0.15,
                'contrast': 0.15,
                'symmetry': 0.15,
                'eyes': 0.10,
                'pose': 0.10,
                'resolution': 0.10
            }
            
            overall_score = (
                sharpness_score * quality_weights['sharpness'] +
                brightness_score * quality_weights['brightness'] +
                contrast_score * quality_weights['contrast'] +
                symmetry_score * quality_weights['symmetry'] +
                eye_quality_score * quality_weights['eyes'] +
                pose_score * quality_weights['pose'] +
                resolution_score * quality_weights['resolution']
            )
            
            return {
                "quality_score": max(0.0, min(1.0, overall_score)),
                "metrics": {
                    "sharpness": sharpness_score,
                    "brightness": brightness_score,
                    "contrast": contrast_score,
                    "symmetry": symmetry_score,
                    "eye_quality": eye_quality_score,
                    "pose_quality": pose_score,
                    "resolution": resolution_score
                },
                "raw_values": {
                    "laplacian_variance": laplacian_var,
                    "brightness_mean": brightness,
                    "contrast_std": contrast,
                    "symmetry_correlation": symmetry_correlation,
                    "eyes_detected": len(eyes),
                    "face_area_pixels": face_area
                }
            }
            
        except Exception as e:
            logger.error(f"Face quality assessment failed: {e}")
            return {
                "quality_score": 0.5,
                "metrics": {},
                "raw_values": {},
                "error": str(e)
            }
    
    @staticmethod
    def _assess_head_pose(gray_image: np.ndarray) -> float:
        """Assess head pose quality (frontal vs profile)"""
        try:
            # Simple pose assessment using eye and nose detection
            eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
            nose_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_profileface.xml')
            
            eyes = eye_cascade.detectMultiScale(gray_image, 1.1, 4)
            profile = nose_cascade.detectMultiScale(gray_image, 1.1, 4)
            
            # Good frontal pose: 2 eyes detected, no strong profile
            if len(eyes) >= 2 and len(profile) == 0:
                return 1.0
            elif len(eyes) == 1:
                return 0.6
            elif len(profile) > 0:
                return 0.3  # Profile pose detected
            else:
                return 0.7  # Default moderate score
                
        except Exception:
            return 0.5
    
    @staticmethod
    async def detect_spoofing(image: np.ndarray, face_location: Tuple[int, int, int, int]) -> Dict[str, Any]:
        """
        Anti-spoofing analysis to detect photo/video attacks.
        
        Args:
            image: OpenCV image
            face_location: Face bounding box (top, right, bottom, left)
            
        Returns:
            Dict containing spoofing analysis results
        """
        try:
            top, right, bottom, left = face_location
            face_region = image[top:bottom, left:right]
            
            if face_region.size == 0:
                return {"spoofing_score": 1.0, "is_likely_spoof": True, "confidence": 0.0}
            
            # 1. Texture Analysis (LBP - Local Binary Patterns)
            texture_score = BiometricHelpers._analyze_texture_lbp(face_region)
            
            # 2. Color Analysis (skin tone distribution)
            color_score = BiometricHelpers._analyze_color_distribution(face_region)
            
            # 3. Frequency Domain Analysis
            frequency_score = BiometricHelpers._analyze_frequency_domain(face_region)
            
            # 4. Reflection Analysis (specular highlights)
            reflection_score = BiometricHelpers._analyze_reflections(face_region)
            
            # 5. Micro-texture Analysis
            micro_texture_score = BiometricHelpers._analyze_micro_texture(face_region)
            
            # Calculate overall spoofing probability
            spoofing_indicators = [
                texture_score * 0.3,
                color_score * 0.2,
                frequency_score * 0.2,
                reflection_score * 0.15,
                micro_texture_score * 0.15
            ]
            
            spoofing_score = sum(spoofing_indicators)
            is_likely_spoof = spoofing_score > 0.6
            confidence = abs(spoofing_score - 0.5) * 2  # Distance from uncertain (0.5)
            
            return {
                "spoofing_score": spoofing_score,
                "is_likely_spoof": is_likely_spoof,
                "confidence": confidence,
                "analysis_details": {
                    "texture_analysis": texture_score,
                    "color_analysis": color_score,
                    "frequency_analysis": frequency_score,
                    "reflection_analysis": reflection_score,
                    "micro_texture_analysis": micro_texture_score
                }
            }
            
        except Exception as e:
            logger.error(f"Spoofing detection failed: {e}")
            return {
                "spoofing_score": 0.5,
                "is_likely_spoof": False,
                "confidence": 0.0,
                "error": str(e)
            }
    
    @staticmethod
    def _analyze_texture_lbp(face_region: np.ndarray) -> float:
        """Analyze texture using Local Binary Patterns"""
        try:
            from skimage.feature import local_binary_pattern
            
            gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY) if len(face_region.shape) == 3 else face_region
            
            # Calculate LBP
            lbp = local_binary_pattern(gray, 8, 1, method='uniform')
            
            # Calculate histogram
            hist, _ = np.histogram(lbp.ravel(), bins=10, range=(0, 9))
            hist = hist.astype(float)
            hist /= (hist.sum() + 1e-7)
            
            # Real faces have more uniform texture distribution
            uniformity = 1.0 - np.std(hist)
            return max(0.0, min(1.0, uniformity))
            
        except Exception:
            return 0.5
    
    @staticmethod
    def _analyze_color_distribution(face_region: np.ndarray) -> float:
        """Analyze color distribution for skin tone authenticity"""
        try:
            # Convert to HSV for better skin tone analysis
            hsv = cv2.cvtColor(face_region, cv2.COLOR_BGR2HSV)
            
            # Define skin tone ranges in HSV
            skin_lower = np.array([0, 20, 70])
            skin_upper = np.array([20, 255, 255])
            
            # Create mask for skin tones
            skin_mask = cv2.inRange(hsv, skin_lower, skin_upper)
            skin_ratio = np.sum(skin_mask > 0) / skin_mask.size
            
            # Real faces should have reasonable skin tone coverage
            skin_score = min(skin_ratio * 2, 1.0)  # Expect at least 50% skin tones
            
            return skin_score
            
        except Exception:
            return 0.5
    
    @staticmethod
    def _analyze_frequency_domain(face_region: np.ndarray) -> float:
        """Analyze frequency domain characteristics"""
        try:
            gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY) if len(face_region.shape) == 3 else face_region
            
            # Apply FFT
            f_transform = np.fft.fft2(gray)
            f_shift = np.fft.fftshift(f_transform)
            magnitude_spectrum = np.log(np.abs(f_shift) + 1)
            
            # Analyze high frequency content (real faces have more natural frequency distribution)
            height, width = magnitude_spectrum.shape
            center_y, center_x = height // 2, width // 2
            
            # Calculate energy in different frequency bands
            high_freq_mask = np.zeros((height, width))
            cv2.circle(high_freq_mask, (center_x, center_y), min(height, width) // 4, 1, -1)
            
            high_freq_energy = np.sum(magnitude_spectrum * high_freq_mask)
            total_energy = np.sum(magnitude_spectrum)
            
            high_freq_ratio = high_freq_energy / (total_energy + 1e-7)
            
            # Real faces typically have moderate high-frequency content
            naturalness_score = 1.0 - abs(high_freq_ratio - 0.3) / 0.3
            return max(0.0, min(1.0, naturalness_score))
            
        except Exception:
            return 0.5
    
    @staticmethod
    def _analyze_reflections(face_region: np.ndarray) -> float:
        """Analyze specular reflections (photos often lack natural reflections)"""
        try:
            gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY) if len(face_region.shape) == 3 else face_region
            
            # Find bright regions that could be reflections
            _, bright_regions = cv2.threshold(gray, 200, 255, cv2.THRESH_BINARY)
            
            # Apply morphological operations to find connected bright regions
            kernel = np.ones((3, 3), np.uint8)
            bright_regions = cv2.morphologyEx(bright_regions, cv2.MORPH_CLOSE, kernel)
            
            # Find contours of bright regions
            contours, _ = cv2.findContours(bright_regions, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Analyze reflection characteristics
            total_area = face_region.shape[0] * face_region.shape[1]
            reflection_area = sum(cv2.contourArea(c) for c in contours)
            reflection_ratio = reflection_area / total_area
            
            # Real faces should have some small reflections (eyes, skin highlights)
            # but not too many (which might indicate photo reflections)
            if 0.001 <= reflection_ratio <= 0.05:
                return 1.0  # Good natural reflections
            elif reflection_ratio > 0.1:
                return 0.2  # Too many reflections (likely photo)
            else:
                return 0.7  # Few reflections (acceptable)
                
        except Exception:
            return 0.5
    
    @staticmethod
    def _analyze_micro_texture(face_region: np.ndarray) -> float:
        """Analyze micro-texture patterns using edge density"""
        try:
            gray = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY) if len(face_region.shape) == 3 else face_region
            
            # Apply multiple edge detection methods
            sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
            sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
            sobel_magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
            
            canny_edges = cv2.Canny(gray, 50, 150)
            
            # Calculate edge density
            sobel_density = np.mean(sobel_magnitude) / 255.0
            canny_density = np.mean(canny_edges) / 255.0
            
            # Real faces have moderate edge density (skin texture, features)
            average_density = (sobel_density + canny_density) / 2
            
            # Optimal range for natural face texture
            if 0.1 <= average_density <= 0.4:
                return 1.0
            else:
                return max(0.0, 1.0 - abs(average_density - 0.25) / 0.25)
                
        except Exception:
            return 0.5
    
    @staticmethod
    async def analyze_face_geometry(image: np.ndarray, face_location: Tuple[int, int, int, int]) -> Dict[str, Any]:
        """Analyze facial geometry and proportions"""
        try:
            top, right, bottom, left = face_location
            face_width = right - left
            face_height = bottom - top
            
            # Basic geometric ratios
            aspect_ratio = face_width / face_height if face_height > 0 else 0
            
            # Extract face region
            face_region = image[top:bottom, left:right]
            gray_face = cv2.cvtColor(face_region, cv2.COLOR_BGR2GRAY) if len(face_region.shape) == 3 else face_region
            
            # Eye detection for inter-ocular distance
            eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
            eyes = eye_cascade.detectMultiScale(gray_face, 1.1, 4)
            
            inter_ocular_distance = 0
            eye_symmetry = 0
            
            if len(eyes) >= 2:
                # Sort eyes by x-coordinate
                eyes = sorted(eyes, key=lambda x: x[0])
                eye1_center = (eyes[0][0] + eyes[0][2]//2, eyes[0][1] + eyes[0][3]//2)
                eye2_center = (eyes[1][0] + eyes[1][2]//2, eyes[1][1] + eyes[1][3]//2)
                
                inter_ocular_distance = np.sqrt((eye2_center[0] - eye1_center[0])**2 + 
                                               (eye2_center[1] - eye1_center[1])**2)
                
                # Eye symmetry (y-coordinate difference)
                eye_y_diff = abs(eye1_center[1] - eye2_center[1])
                eye_symmetry = max(0, 1.0 - eye_y_diff / face_height)
            
            return {
                "face_dimensions": {
                    "width": face_width,
                    "height": face_height,
                    "aspect_ratio": aspect_ratio
                },
                "eye_analysis": {
                    "eyes_detected": len(eyes),
                    "inter_ocular_distance": inter_ocular_distance,
                    "eye_symmetry": eye_symmetry
                },
                "proportions": {
                    "width_height_ratio": aspect_ratio,
                    "eye_distance_face_width_ratio": inter_ocular_distance / face_width if face_width > 0 else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Face geometry analysis failed: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def calculate_final_quality_score(quality_analysis: Dict[str, Any], 
                                    spoofing_analysis: Dict[str, Any],
                                    geometric_analysis: Dict[str, Any]) -> float:
        """Calculate final quality score combining all analyses"""
        try:
            base_quality = quality_analysis.get("quality_score", 0.5)
            spoofing_penalty = spoofing_analysis.get("spoofing_score", 0.5)
            
            # Geometric quality factors
            geometric_factors = geometric_analysis.get("eye_analysis", {})
            eye_symmetry = geometric_factors.get("eye_symmetry", 0.5)
            eyes_detected = geometric_factors.get("eyes_detected", 0)
            
            eye_bonus = 0.1 if eyes_detected >= 2 else 0
            symmetry_bonus = eye_symmetry * 0.1
            
            # Anti-spoofing penalty
            spoofing_penalty_factor = min(spoofing_penalty * 0.3, 0.3)
            
            final_score = base_quality + eye_bonus + symmetry_bonus - spoofing_penalty_factor
            
            return max(0.0, min(1.0, final_score))
            
        except Exception:
            return 0.5
    
    # Additional helper methods for liveness detection would go here...
    # (motion analysis, temporal consistency, eye blink detection, etc.)
    
    @staticmethod
    async def analyze_frame_for_liveness(frame: np.ndarray, timestamp: float) -> Dict[str, Any]:
        """Analyze single video frame for liveness indicators"""
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            # Face detection
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            faces = face_cascade.detectMultiScale(gray, 1.1, 4)
            
            if len(faces) == 0:
                return {
                    "face_detected": False,
                    "timestamp": timestamp,
                    "quality_score": 0.0,
                    "liveness_indicators": {}
                }
            
            # Use largest face
            face = max(faces, key=lambda x: x[2] * x[3])
            x, y, w, h = face
            
            # Quality assessment
            face_region = gray[y:y+h, x:x+w]
            quality_metrics = await BiometricHelpers.assess_face_quality(frame[y:y+h, x:x+w])
            
            # Liveness indicators
            liveness_indicators = {
                "brightness_variation": np.std(face_region),
                "edge_density": np.mean(cv2.Canny(face_region, 50, 150)) / 255.0,
                "texture_uniformity": 1.0 - np.std(face_region) / 255.0
            }
            
            return {
                "face_detected": True,
                "face_location": {"x": x, "y": y, "width": w, "height": h},
                "timestamp": timestamp,
                "quality_score": quality_metrics.get("quality_score", 0.5),
                "liveness_indicators": liveness_indicators
            }
            
        except Exception as e:
            logger.error(f"Frame liveness analysis failed: {e}")
            return {
                "face_detected": False,
                "timestamp": timestamp,
                "quality_score": 0.0,
                "liveness_indicators": {},
                "error": str(e)
            }
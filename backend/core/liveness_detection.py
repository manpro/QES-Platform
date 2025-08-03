"""
Advanced Liveness Detection Algorithms

Implements sophisticated liveness detection methods including motion analysis,
eye blink detection, 3D movement tracking, and temporal consistency checks.
"""

import logging
import numpy as np
import cv2
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from scipy import signal
from scipy.stats import pearsonr

logger = logging.getLogger(__name__)


class LivenessDetectionHelpers:
    """Advanced liveness detection algorithms"""
    
    @staticmethod
    def analyze_motion_patterns(face_positions: List[Dict[str, Any]], fps: float) -> Dict[str, Any]:
        """
        Analyze facial motion patterns for liveness indicators.
        
        Args:
            face_positions: List of face positions over time
            fps: Video frame rate
            
        Returns:
            Dict containing motion analysis results
        """
        try:
            if len(face_positions) < 3:
                return {
                    "motion_detected": False,
                    "motion_score": 0.0,
                    "natural_movement": False,
                    "error": "Insufficient frames for motion analysis"
                }
            
            # Extract center coordinates
            centers = []
            for pos in face_positions:
                if isinstance(pos, dict) and all(k in pos for k in ['x', 'y', 'width', 'height']):
                    center_x = pos['x'] + pos['width'] // 2
                    center_y = pos['y'] + pos['height'] // 2
                    centers.append((center_x, center_y))
            
            if len(centers) < 3:
                return {"motion_detected": False, "motion_score": 0.0, "natural_movement": False}
            
            # Calculate movement vectors
            movements = []
            for i in range(1, len(centers)):
                dx = centers[i][0] - centers[i-1][0]
                dy = centers[i][1] - centers[i-1][1]
                distance = np.sqrt(dx**2 + dy**2)
                movements.append(distance)
            
            # Motion statistics
            avg_movement = np.mean(movements)
            max_movement = np.max(movements)
            movement_std = np.std(movements)
            
            # Detect periodic patterns (natural head movements)
            if len(movements) > 10:
                # Apply FFT to detect periodic movement
                fft_movements = np.fft.fft(movements)
                frequencies = np.fft.fftfreq(len(movements), 1.0/fps)
                
                # Find dominant frequency
                magnitude = np.abs(fft_movements)
                dominant_freq_idx = np.argmax(magnitude[1:len(magnitude)//2]) + 1
                dominant_frequency = abs(frequencies[dominant_freq_idx])
                
                # Natural movement frequency typically 0.1-2 Hz
                natural_freq_range = 0.1 <= dominant_frequency <= 2.0
            else:
                natural_freq_range = True  # Assume natural for short sequences
                dominant_frequency = 0.0
            
            # Calculate motion scores
            motion_detected = avg_movement > 2.0  # Pixels
            motion_score = min(avg_movement / 20.0, 1.0)  # Normalize to 0-1
            
            # Natural movement indicators
            # 1. Reasonable movement amount (not too static, not too erratic)
            reasonable_movement = 2.0 <= avg_movement <= 50.0
            # 2. Variation in movement (not perfectly constant)
            movement_variation = movement_std > 1.0
            # 3. Natural frequency range
            natural_movement = reasonable_movement and movement_variation and natural_freq_range
            
            return {
                "motion_detected": motion_detected,
                "motion_score": motion_score,
                "natural_movement": natural_movement,
                "statistics": {
                    "average_movement": avg_movement,
                    "max_movement": max_movement,
                    "movement_std": movement_std,
                    "dominant_frequency": dominant_frequency,
                    "frames_analyzed": len(movements)
                },
                "indicators": {
                    "reasonable_movement": reasonable_movement,
                    "movement_variation": movement_variation,
                    "natural_frequency": natural_freq_range
                }
            }
            
        except Exception as e:
            logger.error(f"Motion pattern analysis failed: {e}")
            return {
                "motion_detected": False,
                "motion_score": 0.0,
                "natural_movement": False,
                "error": str(e)
            }
    
    @staticmethod
    def analyze_temporal_consistency(liveness_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze temporal consistency of liveness indicators across frames.
        
        Args:
            liveness_scores: List of per-frame liveness indicator dictionaries
            
        Returns:
            Dict containing temporal consistency analysis
        """
        try:
            if len(liveness_scores) < 3:
                return {
                    "consistency_score": 0.5,
                    "temporal_stability": False,
                    "error": "Insufficient frames for temporal analysis"
                }
            
            # Extract consistent metrics across frames
            brightness_values = []
            edge_density_values = []
            texture_values = []
            
            for score_dict in liveness_scores:
                if isinstance(score_dict, dict):
                    brightness_values.append(score_dict.get('brightness_variation', 0))
                    edge_density_values.append(score_dict.get('edge_density', 0))
                    texture_values.append(score_dict.get('texture_uniformity', 0))
            
            if not brightness_values:
                return {"consistency_score": 0.5, "temporal_stability": False}
            
            # Calculate temporal consistency metrics
            def calculate_consistency(values):
                if len(values) < 2:
                    return 0.5
                
                # Coefficient of variation (lower is more consistent)
                mean_val = np.mean(values)
                std_val = np.std(values)
                cv = std_val / (mean_val + 1e-7)
                
                # Convert to consistency score (0-1, higher is more consistent)
                consistency = max(0.0, 1.0 - min(cv, 1.0))
                return consistency
            
            brightness_consistency = calculate_consistency(brightness_values)
            edge_consistency = calculate_consistency(edge_density_values)
            texture_consistency = calculate_consistency(texture_values)
            
            # Overall consistency score
            overall_consistency = (
                brightness_consistency * 0.4 +
                edge_consistency * 0.3 +
                texture_consistency * 0.3
            )
            
            # Detect sudden changes (potential spoofing transitions)
            sudden_changes = 0
            for values in [brightness_values, edge_density_values, texture_values]:
                if len(values) > 1:
                    diffs = np.abs(np.diff(values))
                    mean_diff = np.mean(diffs)
                    sudden_changes += sum(1 for d in diffs if d > mean_diff * 3)
            
            # Temporal stability (fewer sudden changes indicates more stability)
            max_changes = len(liveness_scores) * 3  # 3 metrics
            stability_score = max(0.0, 1.0 - sudden_changes / max_changes)
            temporal_stability = stability_score > 0.7
            
            return {
                "consistency_score": overall_consistency,
                "temporal_stability": temporal_stability,
                "stability_score": stability_score,
                "detailed_consistency": {
                    "brightness_consistency": brightness_consistency,
                    "edge_consistency": edge_consistency,
                    "texture_consistency": texture_consistency
                },
                "change_detection": {
                    "sudden_changes_detected": sudden_changes,
                    "frames_analyzed": len(liveness_scores)
                }
            }
            
        except Exception as e:
            logger.error(f"Temporal consistency analysis failed: {e}")
            return {
                "consistency_score": 0.5,
                "temporal_stability": False,
                "error": str(e)
            }
    
    @staticmethod
    async def detect_eye_blinks(key_frames: List[Dict[str, Any]], video_path: str) -> Dict[str, Any]:
        """
        Detect eye blinks in video for liveness verification.
        
        Args:
            key_frames: List of key frame information
            video_path: Path to video file for detailed analysis
            
        Returns:
            Dict containing eye blink analysis results
        """
        try:
            if len(key_frames) < 10:  # Need sufficient frames
                return {
                    "blinks_detected": 0,
                    "blink_rate": 0.0,
                    "natural_blinking": False,
                    "error": "Insufficient frames for blink detection"
                }
            
            # Eye aspect ratio calculation for blink detection
            eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return {"blinks_detected": 0, "blink_rate": 0.0, "natural_blinking": False}
            
            ear_values = []  # Eye Aspect Ratio values
            timestamps = []
            
            # Analyze frames for eye states
            for frame_info in key_frames:
                frame_idx = frame_info.get('frame_index', 0)
                timestamp = frame_info.get('timestamp', 0)
                
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                
                if not ret:
                    continue
                
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                
                # Detect eyes in frame
                eyes = eye_cascade.detectMultiScale(gray, 1.1, 4)
                
                if len(eyes) >= 2:
                    # Calculate average eye aspect ratio
                    ear_sum = 0
                    for (ex, ey, ew, eh) in eyes[:2]:  # Use first two eyes
                        # Simple EAR approximation using bounding box
                        ear = eh / ew if ew > 0 else 0
                        ear_sum += ear
                    
                    avg_ear = ear_sum / min(len(eyes), 2)
                    ear_values.append(avg_ear)
                    timestamps.append(timestamp)
            
            cap.release()
            
            if len(ear_values) < 5:
                return {"blinks_detected": 0, "blink_rate": 0.0, "natural_blinking": False}
            
            # Detect blinks using EAR threshold
            ear_array = np.array(ear_values)
            ear_mean = np.mean(ear_array)
            ear_std = np.std(ear_array)
            
            # Blink threshold (typically 2 standard deviations below mean)
            blink_threshold = ear_mean - (1.5 * ear_std)
            
            # Find blink events (consecutive frames below threshold)
            below_threshold = ear_array < blink_threshold
            
            # Count blink sequences
            blinks_detected = 0
            in_blink = False
            blink_durations = []
            blink_start = 0
            
            for i, is_blink in enumerate(below_threshold):
                if is_blink and not in_blink:
                    # Start of blink
                    in_blink = True
                    blink_start = i
                elif not is_blink and in_blink:
                    # End of blink
                    in_blink = False
                    blinks_detected += 1
                    blink_duration = timestamps[i] - timestamps[blink_start] if blink_start < len(timestamps) else 0
                    blink_durations.append(blink_duration)
            
            # Calculate blink rate (blinks per minute)
            total_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1
            blink_rate = (blinks_detected / total_duration) * 60 if total_duration > 0 else 0
            
            # Natural blinking assessment
            # Normal blink rate: 12-20 blinks per minute
            # Normal blink duration: 0.1-0.4 seconds
            natural_blink_rate = 5 <= blink_rate <= 30  # Relaxed range for video
            
            avg_blink_duration = np.mean(blink_durations) if blink_durations else 0
            natural_blink_duration = 0.05 <= avg_blink_duration <= 0.8 if avg_blink_duration > 0 else False
            
            natural_blinking = natural_blink_rate and (not blink_durations or natural_blink_duration)
            
            return {
                "blinks_detected": blinks_detected,
                "blink_rate": blink_rate,
                "natural_blinking": natural_blinking,
                "analysis_details": {
                    "average_blink_duration": avg_blink_duration,
                    "blink_durations": blink_durations,
                    "ear_statistics": {
                        "mean": ear_mean,
                        "std": ear_std,
                        "threshold": blink_threshold
                    },
                    "frames_analyzed": len(ear_values),
                    "total_duration": total_duration
                },
                "indicators": {
                    "natural_blink_rate": natural_blink_rate,
                    "natural_blink_duration": natural_blink_duration
                }
            }
            
        except Exception as e:
            logger.error(f"Eye blink detection failed: {e}")
            return {
                "blinks_detected": 0,
                "blink_rate": 0.0,
                "natural_blinking": False,
                "error": str(e)
            }
    
    @staticmethod
    def analyze_3d_movement(face_positions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze 3D-like movement patterns from 2D face tracking.
        
        Args:
            face_positions: List of face position dictionaries
            
        Returns:
            Dict containing 3D movement analysis
        """
        try:
            if len(face_positions) < 5:
                return {
                    "movement_3d_score": 0.0,
                    "depth_variation_detected": False,
                    "rotation_detected": False,
                    "error": "Insufficient positions for 3D analysis"
                }
            
            # Extract face dimensions and positions
            widths = []
            heights = []
            centers = []
            
            for pos in face_positions:
                if isinstance(pos, dict) and all(k in pos for k in ['x', 'y', 'width', 'height']):
                    widths.append(pos['width'])
                    heights.append(pos['height'])
                    centers.append((pos['x'] + pos['width']//2, pos['y'] + pos['height']//2))
            
            if len(widths) < 5:
                return {"movement_3d_score": 0.0, "depth_variation_detected": False, "rotation_detected": False}
            
            # 1. Depth variation analysis (face size changes)
            width_variation = np.std(widths) / np.mean(widths) if np.mean(widths) > 0 else 0
            height_variation = np.std(heights) / np.mean(heights) if np.mean(heights) > 0 else 0
            
            # Reasonable depth variation indicates 3D movement
            depth_variation = (width_variation + height_variation) / 2
            depth_variation_detected = 0.05 <= depth_variation <= 0.3  # 5-30% size variation
            
            # 2. Rotation analysis (aspect ratio changes)
            aspect_ratios = [w/h if h > 0 else 1.0 for w, h in zip(widths, heights)]
            aspect_variation = np.std(aspect_ratios) / np.mean(aspect_ratios) if np.mean(aspect_ratios) > 0 else 0
            
            rotation_detected = aspect_variation > 0.02  # 2% aspect ratio variation
            
            # 3. Trajectory analysis
            if len(centers) >= 3:
                x_coords = [c[0] for c in centers]
                y_coords = [c[1] for c in centers]
                
                # Calculate trajectory curvature
                x_diffs = np.diff(x_coords)
                y_diffs = np.diff(y_coords)
                
                # Curvature approximation
                if len(x_diffs) > 1:
                    curvatures = []
                    for i in range(1, len(x_diffs)):
                        # Change in direction
                        prev_angle = np.arctan2(y_diffs[i-1], x_diffs[i-1])
                        curr_angle = np.arctan2(y_diffs[i], x_diffs[i])
                        angle_change = abs(curr_angle - prev_angle)
                        curvatures.append(angle_change)
                    
                    avg_curvature = np.mean(curvatures) if curvatures else 0
                    curved_trajectory = avg_curvature > 0.1  # Some curvature indicates natural movement
                else:
                    curved_trajectory = False
            else:
                curved_trajectory = False
            
            # 4. Overall 3D movement score
            depth_score = min(depth_variation / 0.2, 1.0) if depth_variation_detected else 0
            rotation_score = min(aspect_variation / 0.1, 1.0) if rotation_detected else 0
            trajectory_score = 0.5 if curved_trajectory else 0
            
            movement_3d_score = (depth_score * 0.5 + rotation_score * 0.3 + trajectory_score * 0.2)
            
            return {
                "movement_3d_score": movement_3d_score,
                "depth_variation_detected": depth_variation_detected,
                "rotation_detected": rotation_detected,
                "analysis_details": {
                    "depth_variation": depth_variation,
                    "aspect_variation": aspect_variation,
                    "curved_trajectory": curved_trajectory,
                    "width_stats": {
                        "mean": np.mean(widths),
                        "std": np.std(widths),
                        "variation_coeff": width_variation
                    },
                    "height_stats": {
                        "mean": np.mean(heights),
                        "std": np.std(heights),
                        "variation_coeff": height_variation
                    }
                },
                "indicators": {
                    "natural_depth_changes": depth_variation_detected,
                    "head_rotation": rotation_detected,
                    "natural_trajectory": curved_trajectory
                }
            }
            
        except Exception as e:
            logger.error(f"3D movement analysis failed: {e}")
            return {
                "movement_3d_score": 0.0,
                "depth_variation_detected": False,
                "rotation_detected": False,
                "error": str(e)
            }
    
    @staticmethod
    def calculate_liveness_score(motion_analysis: Dict[str, Any],
                               temporal_analysis: Dict[str, Any],
                               blink_analysis: Dict[str, Any],
                               movement_analysis: Dict[str, Any]) -> float:
        """
        Calculate final liveness score from all analyses.
        
        Args:
            motion_analysis: Motion pattern analysis results
            temporal_analysis: Temporal consistency results
            blink_analysis: Eye blink detection results
            movement_analysis: 3D movement analysis results
            
        Returns:
            Final liveness score (0.0 to 1.0)
        """
        try:
            # Extract individual scores
            motion_score = motion_analysis.get("motion_score", 0.0)
            natural_movement = motion_analysis.get("natural_movement", False)
            
            consistency_score = temporal_analysis.get("consistency_score", 0.5)
            temporal_stability = temporal_analysis.get("temporal_stability", False)
            
            blinks_detected = blink_analysis.get("blinks_detected", 0)
            natural_blinking = blink_analysis.get("natural_blinking", False)
            
            movement_3d_score = movement_analysis.get("movement_3d_score", 0.0)
            depth_variation = movement_analysis.get("depth_variation_detected", False)
            
            # Weight different indicators
            weights = {
                "motion": 0.25,
                "temporal": 0.20,
                "blinks": 0.25,
                "movement_3d": 0.20,
                "bonuses": 0.10
            }
            
            # Base scores
            motion_component = motion_score * weights["motion"]
            temporal_component = consistency_score * weights["temporal"]
            
            # Blink component
            blink_score = 0.0
            if blinks_detected > 0:
                blink_score = 0.8 if natural_blinking else 0.5
            blink_component = blink_score * weights["blinks"]
            
            # 3D movement component
            movement_component = movement_3d_score * weights["movement_3d"]
            
            # Bonus factors
            bonus_score = 0.0
            if natural_movement:
                bonus_score += 0.3
            if temporal_stability:
                bonus_score += 0.3
            if depth_variation:
                bonus_score += 0.4
            
            bonus_component = min(bonus_score, 1.0) * weights["bonuses"]
            
            # Calculate final score
            final_score = (
                motion_component +
                temporal_component +
                blink_component +
                movement_component +
                bonus_component
            )
            
            # Apply penalties for obvious non-liveness indicators
            penalties = 0.0
            
            # No motion detected
            if not motion_analysis.get("motion_detected", False):
                penalties += 0.3
            
            # No temporal stability (sudden changes)
            if not temporal_stability:
                penalties += 0.2
            
            # No natural indicators
            if not any([natural_movement, natural_blinking, depth_variation]):
                penalties += 0.2
            
            final_score = max(0.0, final_score - penalties)
            
            return min(1.0, final_score)
            
        except Exception as e:
            logger.error(f"Liveness score calculation failed: {e}")
            return 0.3  # Conservative low score on error
    
    @staticmethod
    def compare_face_geometry(geometry1: Dict[str, Any], geometry2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare geometric properties of two faces"""
        try:
            if not geometry1 or not geometry2:
                return {"similarity": 0.5, "comparison_possible": False}
            
            dims1 = geometry1.get("face_dimensions", {})
            dims2 = geometry2.get("face_dimensions", {})
            
            if not dims1 or not dims2:
                return {"similarity": 0.5, "comparison_possible": False}
            
            # Compare aspect ratios
            ratio1 = dims1.get("aspect_ratio", 1.0)
            ratio2 = dims2.get("aspect_ratio", 1.0)
            
            ratio_similarity = 1.0 - abs(ratio1 - ratio2) / max(ratio1, ratio2, 0.1)
            
            # Compare eye analysis if available
            eyes1 = geometry1.get("eye_analysis", {})
            eyes2 = geometry2.get("eye_analysis", {})
            
            eye_similarity = 0.5  # Default
            if eyes1 and eyes2:
                eye_sym1 = eyes1.get("eye_symmetry", 0.5)
                eye_sym2 = eyes2.get("eye_symmetry", 0.5)
                eye_similarity = 1.0 - abs(eye_sym1 - eye_sym2)
            
            overall_similarity = (ratio_similarity * 0.6 + eye_similarity * 0.4)
            
            return {
                "similarity": overall_similarity,
                "comparison_possible": True,
                "details": {
                    "aspect_ratio_similarity": ratio_similarity,
                    "eye_symmetry_similarity": eye_similarity
                }
            }
            
        except Exception as e:
            logger.error(f"Face geometry comparison failed: {e}")
            return {"similarity": 0.5, "comparison_possible": False, "error": str(e)}
    
    @staticmethod
    def compare_quality_metrics(quality1: Dict[str, Any], quality2: Dict[str, Any]) -> Dict[str, Any]:
        """Compare quality metrics between two face analyses"""
        try:
            if not quality1 or not quality2:
                return {"similarity": 0.5, "comparison_possible": False}
            
            metrics1 = quality1.get("metrics", {})
            metrics2 = quality2.get("metrics", {})
            
            if not metrics1 or not metrics2:
                return {"similarity": 0.5, "comparison_possible": False}
            
            # Compare common metrics
            common_metrics = ["sharpness", "brightness", "contrast", "symmetry"]
            similarities = []
            
            for metric in common_metrics:
                val1 = metrics1.get(metric, 0.5)
                val2 = metrics2.get(metric, 0.5)
                
                similarity = 1.0 - abs(val1 - val2)
                similarities.append(similarity)
            
            overall_similarity = np.mean(similarities) if similarities else 0.5
            
            return {
                "similarity": overall_similarity,
                "comparison_possible": True,
                "metric_similarities": dict(zip(common_metrics, similarities))
            }
            
        except Exception as e:
            logger.error(f"Quality metrics comparison failed: {e}")
            return {"similarity": 0.5, "comparison_possible": False, "error": str(e)}
"""
face_engine.py — Phase 2 recognition engine.

Design decision (documented for the project report):
  Phase 1's plan assumed a dlib/face_recognition-based pipeline. That library requires
  compiling `dlib` from source on most platforms (needs cmake + a C++ toolchain), which is
  a common, hard-to-debug installation failure point for students on Windows and a real risk
  right before a demo. OpenCV's Haar cascade (detection) + LBPH (recognition) ships as a
  prebuilt wheel via `opencv-contrib-python` — installs in seconds, no compiler needed — and
  is a well-established, legitimate approach for classroom-scale attendance systems. It is
  slightly less accurate than deep-learning embeddings, but reliability of installation for a
  final-year submission outweighs a marginal accuracy gain here. Phase 5 can revisit stronger
  models if desired once the base system is proven.

Data model note:
  students.face_encoding stores a base64-encoded JPEG of a normalized 200x200 grayscale face
  crop (not a numeric vector). LBPH trains on these crops directly, so this is the most
  natural storage format for this recognition backend while keeping Phase 1's schema field
  reusable as-is.

Tunable thresholds below are heuristics — recalibrate them after testing with your actual
classroom camera and lighting; LBPH's "confidence" is a distance (lower = better match), not
a percentage, and its scale depends on your image quality.
"""

import base64
import io

import cv2
import numpy as np
from PIL import Image

FACE_SIZE = (200, 200)

# Phase 3 registration wizard poses, in capture order. 'front' alone is enough to make a
# student recognizable (and is what Phase 2's quick "generate from photo" path produces);
# capturing the rest measurably improves robustness to head angle and lighting.
POSE_LIST = ['front', 'left', 'right', 'up', 'down', 'neutral', 'smile', 'glasses', 'no_glasses']
POSE_LABELS = {
    'front': 'Look straight at the camera',
    'left': 'Turn your head slightly left',
    'right': 'Turn your head slightly right',
    'up': 'Tilt your head slightly up',
    'down': 'Tilt your head slightly down',
    'neutral': 'Neutral expression',
    'smile': 'Smile',
    'glasses': 'Wearing glasses (skip if you don\'t wear any)',
    'no_glasses': 'Without glasses',
}

# True only if the opencv-contrib "face" module (LBPH) is present. Some environments only
# have plain opencv-python installed, which lacks cv2.face — degrade gracefully to manual
# attendance instead of crashing if so.
CASCADE_AVAILABLE = hasattr(cv2, 'face')

# LBPH distance thresholds (lower distance = better match). Tune these after real-world testing.
GOOD_MATCH_DISTANCE = 55      # at/below this -> confident match, auto-mark present
BORDERLINE_DISTANCE = 85      # between GOOD and this -> flagged for manual verification
# above BORDERLINE_DISTANCE -> treated as unknown/unrecognized

_face_cascade = None
_eye_cascade = None


def get_cascade():
    global _face_cascade
    if _face_cascade is None:
        path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        _face_cascade = cv2.CascadeClassifier(path)
    return _face_cascade


def get_eye_cascade():
    global _eye_cascade
    if _eye_cascade is None:
        path = cv2.data.haarcascades + 'haarcascade_eye.xml'
        _eye_cascade = cv2.CascadeClassifier(path)
    return _eye_cascade


def eyes_detected_in_face(gray_image, box):
    """
    Phase 5 basic liveness signal. IMPORTANT LIMITATION (documented here and in the README):
    this is NOT robust anti-spoofing. True liveness detection needs facial landmarks (eye
    aspect ratio over time), depth sensing, or a trained model — none of which this Haar-
    cascade stack has. What this DOES do: detect whether eyes are currently visible in the
    face region. Tracked over several observations a few seconds apart (see app.py's
    liveness tracker), a real person will show natural blinks (eyes toggle not-detected
    briefly); a rigid printed photo tends to show constant, unchanging detection. This is a
    weak, explainable deterrent against the simplest spoof (holding up a photo) — it will
    have false positives (people who happen not to blink in the sampling window, glasses
    glare) and does nothing against a video replay attack. It downgrades a match to manual
    review; it never silently blocks anyone.
    """
    x, y, w, h = box
    face_roi = gray_image[y:y + h, x:x + w]
    cascade = get_eye_cascade()
    eyes = cascade.detectMultiScale(face_roi, scaleFactor=1.1, minNeighbors=6, minSize=(15, 15))
    return len(eyes) > 0


def distance_to_confidence(distance):
    """Map an LBPH distance to a 0-100 'confidence' purely for display purposes."""
    return round(max(0.0, 100.0 - distance), 1)


def decode_data_url_to_bgr(data_url):
    """Convert a 'data:image/jpeg;base64,...' string from the browser into an OpenCV BGR image."""
    if ',' in data_url:
        data_url = data_url.split(',', 1)[1]
    binary = base64.b64decode(data_url)
    pil_img = Image.open(io.BytesIO(binary)).convert('RGB')
    rgb = np.array(pil_img)
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def decode_filepath_to_bgr(filepath):
    pil_img = Image.open(filepath).convert('RGB')
    rgb = np.array(pil_img)
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def detect_faces(bgr_image):
    """Return a list of (x, y, w, h) rectangles for every face found in the image."""
    gray = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
    gray = cv2.equalizeHist(gray)
    cascade = get_cascade()
    faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
    return gray, [tuple(int(v) for v in f) for f in faces]


def crop_and_normalize(gray_image, box):
    x, y, w, h = box
    crop = gray_image[y:y + h, x:x + w]
    return cv2.resize(crop, FACE_SIZE)


def encode_face_crop_to_b64(face_crop):
    """Encode a normalized grayscale face crop as a base64 JPEG string for DB storage."""
    ok, buf = cv2.imencode('.jpg', face_crop, [cv2.IMWRITE_JPEG_QUALITY, 90])
    if not ok:
        raise ValueError("Could not encode face crop")
    return base64.b64encode(buf.tobytes()).decode('ascii')


def decode_b64_to_face_crop(b64_str):
    binary = base64.b64decode(b64_str)
    arr = np.frombuffer(binary, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError("Stored face data is corrupted")
    if img.shape != FACE_SIZE:
        img = cv2.resize(img, FACE_SIZE)
    return img


def register_face_from_image(bgr_image):
    """
    Given a full photo (BGR), find exactly one face and return (b64_encoded_crop, error).
    error is None on success.
    """
    gray, boxes = detect_faces(bgr_image)
    if len(boxes) == 0:
        return None, "No face detected in this photo. Use a clear, front-facing photo with good lighting."
    if len(boxes) > 1:
        return None, "Multiple faces detected. Use a photo containing only this student's face."
    crop = crop_and_normalize(gray, boxes[0])
    return encode_face_crop_to_b64(crop), None


def eyes_detected_bgr(bgr_image, box):
    """Convenience wrapper so callers (app.py) never need to import cv2 directly."""
    gray = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
    return eyes_detected_in_face(gray, box)


def build_recognizer(roster_encodings):
    """
    roster_encodings: list of (student_id, b64_face_crop) for everyone enrolled with a
    registered face. Returns a trained LBPH recognizer, or None if nobody is registered yet.
    Kept for backward compatibility (Phase 2's single-photo registration path).
    """
    images, labels = [], []
    for student_id, b64_crop in roster_encodings:
        try:
            images.append(decode_b64_to_face_crop(b64_crop))
            labels.append(int(student_id))
        except Exception:
            continue
    if not images:
        return None
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.train(images, np.array(labels))
    return recognizer


def build_recognizer_from_samples(roster_samples):
    """
    Phase 3: trains on every captured pose per student instead of just one photo. LBPH
    natively supports multiple training images sharing the same label, so a student with
    5 captured angles simply contributes 5 training images under their own student_id —
    this measurably improves robustness to head angle and lighting versus one frontal shot.

    roster_samples: list of (student_id, b64_face_crop) — pass every pose row for every
    enrolled student; duplicate student_ids across multiple poses are expected and desired.
    """
    return build_recognizer(roster_samples)


def recognize_frame(bgr_image, recognizer):
    """
    Detect every face in a frame and, if a recognizer is available, match each one.
    Returns a list of dicts: { 'box': [x,y,w,h], 'student_id': int|None,
                                'confidence': float, 'match': 'present'|'pending_review'|'unknown',
                                'eyes_detected': bool }
    'eyes_detected' feeds the basic liveness heuristic in app.py — see eyes_detected_in_face()
    for its documented limitations.
    """
    gray, boxes = detect_faces(bgr_image)
    results = []
    for box in boxes:
        crop = crop_and_normalize(gray, box)
        eyes_detected = eyes_detected_in_face(gray, box)
        if recognizer is None:
            results.append({'box': list(box), 'student_id': None, 'confidence': 0.0, 'match': 'unknown', 'eyes_detected': eyes_detected})
            continue

        label, distance = recognizer.predict(crop)
        confidence = distance_to_confidence(distance)

        if distance <= GOOD_MATCH_DISTANCE:
            match = 'present'
            student_id = int(label)
        elif distance <= BORDERLINE_DISTANCE:
            match = 'pending_review'
            student_id = int(label)
        else:
            match = 'unknown'
            student_id = None

        results.append({'box': list(box), 'student_id': student_id, 'confidence': confidence, 'match': match, 'eyes_detected': eyes_detected})
    return results

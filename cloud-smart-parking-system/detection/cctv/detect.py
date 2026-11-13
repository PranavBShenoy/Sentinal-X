"""
OpenCV CCTV Vehicle Occupancy Detection Node
Analyzes parking surveillance video frames, calculates pixel density in defined slot bounding boxes,
and pushes occupancy state updates to the Cloud REST API.
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import cv2
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, 'slot_config.json')
DEFAULT_VIDEO_PATH = os.path.join(SCRIPT_DIR, 'sample-video', 'sample_parking.mp4')
DEFAULT_API_URL = 'http://127.0.0.1:5000/api/detection/update'

def load_config(config_path):
    with open(config_path, 'r') as f:
        return json.load(f)

def send_detection_to_api(api_url, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        api_url,
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            res_body = response.read().decode('utf-8')
            return True, res_body
    except urllib.error.URLError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def process_frame(frame, slots, params):
    # Pre-processing pipeline: Gray -> Blur -> Adaptive Threshold
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    ksize = tuple(params.get('gaussianBlurKernel', [5, 5]))
    blur = cv2.GaussianBlur(gray, ksize, 1)

    block_size = params.get('adaptiveThresholdBlockSize', 19)
    c_val = params.get('adaptiveThresholdC', 3)
    thresh = cv2.adaptiveThreshold(
        blur, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, block_size, c_val
    )

    threshold_ratio = params.get('occupancyThreshold', 0.28)
    results = []

    for slot in slots:
        x, y, w, h = slot['x'], slot['y'], slot['width'], slot['height']
        slot_id = slot['slotId']
        area = slot.get('parkingArea', 'Zone A')

        # Crop slot region from thresholded image
        slot_roi = thresh[y:y+h, x:x+w]
        total_pixels = w * h
        non_zero_count = cv2.countNonZero(slot_roi)
        density = non_zero_count / float(total_pixels)

        is_occupied = density >= threshold_ratio
        status = 'OCCUPIED' if is_occupied else 'FREE'

        # Calculate confidence score (distance from decision boundary)
        diff = abs(density - threshold_ratio)
        confidence = min(1.0, 0.70 + (diff / 0.3) * 0.3)

        results.append({
            'slotId': slot_id,
            'status': status,
            'confidence': round(confidence, 2),
            'parkingArea': area,
            'density': round(density, 3)
        })

        # Draw overlay on visualization frame
        box_color = (0, 0, 255) if is_occupied else (0, 255, 0) # Red if occupied, Green if free
        cv2.rectangle(frame, (x, y), (x + w, y + h), box_color, 2)
        label = f"{slot_id}: {status} ({int(confidence*100)}%)"
        cv2.putText(frame, label, (x + 5, y - 8), cv2.FONT_HERSHEY_SIMPLEX, 0.45, box_color, 2)

    return results, frame

def run_detection(video_source, config_path, api_url, max_frames=None, show_gui=False):
    print("==================================================")
    print("🎥 OpenCV CCTV Vehicle Detection Node Starting")
    print(f"📹 Source: {video_source}")
    print(f"⚙️ Config: {config_path}")
    print(f"☁️ Target API: {api_url}")
    print("==================================================")

    config = load_config(config_path)
    slots = config.get('parkingSlots', [])
    params = config.get('detectionParams', {})
    report_interval = params.get('reportIntervalFrames', 15)

    cap = cv2.VideoCapture(int(video_source) if str(video_source).isdigit() else video_source)

    if not cap.isOpened():
        print(f"❌ Error: Could not open video source '{video_source}'.")
        return False

    frame_count = 0
    start_time = time.time()
    last_reported_status = {}

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                # Video ended; if reading file, can loop or exit
                print("[CCTV] Video stream ended.")
                break

            frame_count += 1
            results, vis_frame = process_frame(frame, slots, params)

            # Send updates to Cloud API every report_interval frames or on change
            if frame_count % report_interval == 0:
                payload = {
                    'parkingArea': config.get('facility', 'Zone A'),
                    'source': 'CCTV',
                    'detectionTimestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'slots': [
                        {
                            'slotId': r['slotId'],
                            'status': r['status'],
                            'confidence': r['confidence'],
                            'parkingArea': r['parkingArea'],
                            'source': 'CCTV'
                        }
                        for r in results
                    ]
                }

                success, msg = send_detection_to_api(api_url, payload)
                status_summary = ", ".join([f"{r['slotId']}:{r['status']}" for r in results])
                if success:
                    print(f"[Frame {frame_count:03d}] CCTV -> Cloud API sync OK ({status_summary})")
                else:
                    print(f"[Frame {frame_count:03d}] Cloud API unreachable: {msg}")

            if show_gui:
                cv2.imshow("CCTV Parking Occupancy Monitor", vis_frame)
                if cv2.waitKey(25) & 0xFF == ord('q'):
                    print("[CCTV] Quit signal received.")
                    break

            if max_frames and frame_count >= max_frames:
                print(f"[CCTV] Completed requested {max_frames} frames.")
                break

    finally:
        cap.release()
        if show_gui:
            cv2.destroyAllWindows()

    elapsed = time.time() - start_time
    fps = frame_count / elapsed if elapsed > 0 else 0
    print(f"🏁 Finished processing {frame_count} frames in {elapsed:.2f}s ({fps:.1f} FPS).")
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenCV CCTV Vehicle Occupancy Detection')
    parser.add_argument('--video', default=DEFAULT_VIDEO_PATH, help='Path to video file or webcam index')
    parser.add_argument('--config', default=DEFAULT_CONFIG_PATH, help='Path to slot configuration JSON')
    parser.add_argument('--api-url', default=DEFAULT_API_URL, help='Cloud REST API detection endpoint')
    parser.add_argument('--frames', type=int, default=None, help='Max frames to process')
    parser.add_argument('--show', action='store_true', help='Display OpenCV window visualization')
    args = parser.parse_args()

    run_detection(
        video_source=args.video,
        config_path=args.config,
        api_url=args.api_url,
        max_frames=args.frames,
        show_gui=args.show
    )

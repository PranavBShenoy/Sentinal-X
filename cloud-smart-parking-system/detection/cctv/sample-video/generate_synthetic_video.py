"""
Synthetic Parking CCTV Video Generator
Creates a 150-frame sample video demonstrating vehicles parked and entering parking slots.
Uses OpenCV drawing primitives to produce realistic parking bays and vehicles.
"""

import os
import cv2
import numpy as np

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'sample_parking.mp4')

WIDTH, HEIGHT = 800, 600
FPS = 15
TOTAL_FRAMES = 120

def draw_parking_lot(base_img):
    # Asphalt background
    base_img[:] = (45, 45, 50)
    
    # Driving lane markings (dashed yellow)
    for x in range(30, WIDTH - 30, 40):
        cv2.line(base_img, (x, 420), (x + 20, 420), (0, 215, 255), 2)
        
    # Draw bays (white border lines)
    slots = [
        ("A01", 60, 140, 100, 180),
        ("A02", 180, 140, 100, 180),
        ("A03", 300, 140, 100, 180),
        ("A04", 420, 140, 100, 180),
        ("B01", 540, 140, 100, 180),
        ("B02", 660, 140, 100, 180),
    ]
    
    for slot_id, x, y, w, h in slots:
        # Slot bay borders
        cv2.line(base_img, (x, y), (x, y + h), (220, 220, 220), 3)
        cv2.line(base_img, (x + w, y), (x + w, y + h), (220, 220, 220), 3)
        cv2.line(base_img, (x, y), (x + w, y), (220, 220, 220), 3)
        # Slot label
        cv2.putText(base_img, slot_id, (x + 25, y + 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (180, 180, 180), 2)

def draw_car(img, center_x, center_y, color=(40, 80, 200)):
    # Vehicle body rectangle
    cv2.rectangle(img, (center_x - 35, center_y - 65), (center_x + 35, center_y + 65), color, -1)
    cv2.rectangle(img, (center_x - 35, center_y - 65), (center_x + 35, center_y + 65), (20, 40, 100), 2)
    # Windshield (dark)
    cv2.rectangle(img, (center_x - 28, center_y - 30), (center_x + 28, center_y - 10), (30, 30, 30), -1)
    # Rear window
    cv2.rectangle(img, (center_x - 28, center_y + 25), (center_x + 28, center_y + 45), (30, 30, 30), -1)
    # Roof
    cv2.rectangle(img, (center_x - 26, center_y - 8), (center_x + 26, center_y + 23), color, -1)
    # Headlights
    cv2.circle(img, (center_x - 24, center_y - 60), 4, (120, 255, 255), -1)
    cv2.circle(img, (center_x + 24, center_y - 60), 4, (120, 255, 255), -1)

def generate_video():
    print(f"Generating synthetic CCTV video: {OUTPUT_FILE} ({WIDTH}x{HEIGHT}, {TOTAL_FRAMES} frames)...")
    
    # Try different codecs
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(OUTPUT_FILE, fourcc, FPS, (WIDTH, HEIGHT))
    
    if not out.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        out = cv2.VideoWriter(OUTPUT_FILE, fourcc, FPS, (WIDTH, HEIGHT))
        
    for frame_idx in range(TOTAL_FRAMES):
        frame = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)
        draw_parking_lot(frame)
        
        # Stationary car in A02
        draw_car(frame, 230, 230, color=(180, 50, 40)) # Red car
        
        # Stationary car in B02
        draw_car(frame, 710, 230, color=(40, 150, 60)) # Green car
        
        # Dynamic car entering Slot A01 starting at frame 30
        if frame_idx >= 30:
            progress = min(1.0, (frame_idx - 30) / 45.0)
            # Starts from driving lane (x=110, y=470) and maneuvers into A01 (x=110, y=230)
            cur_y = int(470 - (470 - 230) * progress)
            draw_car(frame, 110, cur_y, color=(40, 100, 210)) # Blue car
            
        # Add frame index and CCTV timestamp overlay
        cv2.putText(frame, f"CAM-01 [LIVE] FRAME: {frame_idx:03d}", (20, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        cv2.putText(frame, "CCTV Parking Node - OpenCV", (20, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
        
        out.write(frame)
        
    out.release()
    print(f"Successfully generated video: {OUTPUT_FILE} (Size: {os.path.getsize(OUTPUT_FILE)} bytes)")

if __name__ == '__main__':
    generate_video()

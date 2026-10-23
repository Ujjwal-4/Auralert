import math
from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 800
img = Image.new('RGB', (W, H), color='#080915')
draw = ImageDraw.Draw(img)

# Radial background glow
center_x, center_y = W // 2, 320
for r in range(460, 0, -3):
    ratio = r / 460.0
    red = int(8 + (32 - 8) * (1 - ratio)**1.5)
    green = int(9 + (24 - 9) * (1 - ratio)**1.5)
    blue = int(21 + (70 - 21) * (1 - ratio)**1.5)
    draw.ellipse([center_x - r, center_y - r, center_x + r, center_y + r], fill=(red, green, blue))

# Grid lines
for x in range(0, W, 40):
    draw.line([(x, 0), (x, H)], fill=(20, 25, 48), width=1)
for y in range(0, H, 40):
    draw.line([(0, y), (W, y)], fill=(20, 25, 48), width=1)

# Crosshairs
draw.line([(center_x - 380, center_y), (center_x + 380, center_y)], fill=(0, 242, 254), width=1)
draw.line([(center_x, center_y - 260), (center_x, center_y + 260)], fill=(0, 242, 254), width=1)

# Concentric Radar rings
rings = [
    (320, (30, 40, 75), 1),
    (270, (0, 180, 210), 1),
    (210, (112, 0, 255), 2),
    (150, (0, 242, 254), 2),
    (100, (0, 242, 254), 3),
    (55, (184, 39, 252), 3),
    (18, (0, 242, 254), 4)
]
for r, color, w in rings:
    draw.ellipse([center_x - r, center_y - r, center_x + r, center_y + r], outline=color, width=w)

# Sine waves
points_cyan = []
points_purple = []
for x in range(80, W - 80):
    env = math.exp(-((x - center_x) / 360.0)**2)
    y_c = center_y + math.sin(x * 0.035) * 65 * env + math.cos(x * 0.012) * 20 * env
    y_p = center_y - math.sin(x * 0.028) * 85 * env - math.cos(x * 0.015) * 30 * env
    points_cyan.append((x, y_c))
    points_purple.append((x, y_p))

for i in range(len(points_cyan) - 1):
    draw.line([points_cyan[i], points_cyan[i+1]], fill=(0, 242, 254), width=2)
    draw.line([points_purple[i], points_purple[i+1]], fill=(184, 39, 252), width=2)

# Central glowing core
draw.ellipse([center_x - 8, center_y - 8, center_x + 8, center_y + 8], fill=(255, 255, 255))
draw.ellipse([center_x - 14, center_y - 14, center_x + 14, center_y + 14], outline=(0, 242, 254), width=2)

# Load fonts
try:
    font_title = ImageFont.truetype('arialbd.ttf', 62)
    font_sub = ImageFont.truetype('arialbd.ttf', 24)
    font_quote = ImageFont.truetype('ariali.ttf', 20)
    font_badge = ImageFont.truetype('arial.ttf', 13)
except Exception:
    font_title = ImageFont.load_default()
    font_sub = ImageFont.load_default()
    font_quote = ImageFont.load_default()
    font_badge = ImageFont.load_default()

# Text Rendering
title_text = "AURALERT"
sub_text = "VOICE-FIRST SCAM DEFENSE"
quote_text = '"Listen Beyond the Lie."'

bbox_t = draw.textbbox((0, 0), title_text, font=font_title)
w_t = bbox_t[2] - bbox_t[0]
draw.text(((W - w_t) // 2, 630), title_text, fill=(255, 255, 255), font=font_title)

bbox_s = draw.textbbox((0, 0), sub_text, font=font_sub)
w_s = bbox_s[2] - bbox_s[0]
draw.text(((W - w_s) // 2, 705), sub_text, fill=(0, 242, 254), font=font_sub)

bbox_q = draw.textbbox((0, 0), quote_text, font=font_quote)
w_q = bbox_q[2] - bbox_q[0]
draw.text(((W - w_q) // 2, 742), quote_text, fill=(195, 202, 235), font=font_quote)

# Top corner badges
draw.text((50, 40), "DEFENSE RADAR // MCP STREAMABLE HTTP", fill=(100, 115, 160), font=font_badge)
draw.text((W - 300, 40), "ALEXA+ HACKATHON 2026", fill=(100, 115, 160), font=font_badge)

# Corner bracket accents
draw.line([(40, 30), (70, 30)], fill=(0, 242, 254), width=2)
draw.line([(40, 30), (40, 60)], fill=(0, 242, 254), width=2)
draw.line([(W - 40, 30), (W - 70, 30)], fill=(0, 242, 254), width=2)
draw.line([(W - 40, 30), (W - 40, 60)], fill=(0, 242, 254), width=2)
draw.line([(40, H - 30), (70, H - 30)], fill=(112, 0, 255), width=2)
draw.line([(40, H - 30), (40, H - 60)], fill=(112, 0, 255), width=2)
draw.line([(W - 40, H - 30), (W - 70, H - 30)], fill=(112, 0, 255), width=2)
draw.line([(W - 40, H - 30), (W - 40, H - 60)], fill=(112, 0, 255), width=2)

img.save('web/auralert-thumbnail.png', 'PNG')
img.save('docs/assets/auralert-thumbnail.png', 'PNG')
print('SUCCESS! Thumbnail generated at 1200x800 (3:2 ratio)')

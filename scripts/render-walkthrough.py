#!/usr/bin/env python3
"""Render our captured asciicast without inventing command output or timing."""
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

source, target = map(Path, sys.argv[1:3])
rows = [json.loads(line) for line in source.read_text().splitlines()]
meta, events = rows[0], rows[1:]
assert meta['version'] == 2
assert events and all(e[1] == 'o' for e in events)
width, height, fps = 1920, 1080, 12
duration = events[-1][0] + 1
font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 25)
small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 21)
label = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 23)
lines, line, pos = [], '', 0

def consume(chunk):
    global lines, line
    # This recorder emits only clear/home plus text. Reject unknown escapes
    # instead of silently rendering an inaccurate terminal session.
    parts = chunk.split('\x1b[2J\x1b[H')
    for index, part in enumerate(parts):
        if index:
            lines, line = [], ''
        if '\x1b' in part:
            raise ValueError('Unsupported terminal escape sequence')
        for ch in part:
            if ch == '\r':
                continue
            if ch == '\n':
                lines.append(line)
                line = ''
            else:
                line += ch
                if len(line) >= meta['width']:
                    lines.append(line)
                    line = ''
        lines = lines[-27:]

cmd = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y', '-f', 'rawvideo',
       '-pix_fmt', 'rgb24', '-s', f'{width}x{height}', '-r', str(fps), '-i', '-',
       '-an', '-c:v', 'libx264', '-preset', 'fast', '-crf', '21', '-pix_fmt',
       'yuv420p', '-movflags', '+faststart', str(target)]
target.parent.mkdir(parents=True, exist_ok=True)
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
try:
    for frame in range(math.ceil(duration * fps)):
        t = frame / fps
        while pos < len(events) and events[pos][0] <= t:
            consume(events[pos][2])
            pos += 1
        im = Image.new('RGB', (width, height), '#0b1120')
        d = ImageDraw.Draw(im)
        d.rounded_rectangle((30, 24, 1890, 1000), radius=18, fill='#121c2d', outline='#30415b', width=2)
        d.text((62, 44), 'ssrf-lab  /  recorded CI execution', font=label, fill='#e8edf5')
        d.text((1330, 47), f'Node {meta.get("node", "24")}  |  isolated Linux', font=small, fill='#aabbd1')
        d.line((32, 89, 1888, 89), fill='#30415b', width=2)
        visible = (lines + [line])[-28:]
        for i, text in enumerate(visible):
            color = '#d9e2f0'
            if 'REACHED' in text or 'CI fails:' in text:
                color = '#ffbb85'
            elif 'BLOCKED' in text or 'CI passes:' in text:
                color = '#76d9f3'
            elif text.startswith('$'):
                color = '#d6b5ff'
            elif text.startswith('ssrf-lab |'):
                color = '#ffffff'
            d.text((62, 113 + i * 30), text, font=font, fill=color)
        d.text((42, 1023), 'Real captured commands + JSON-derived output. Reading pauses are part of the recording.', font=small, fill='#afbdd2')
        d.text((1740, 1023), f'{t:04.1f}s', font=small, fill='#afbdd2')
        d.rectangle((30, 1070, 30 + int(1860 * min(t / duration, 1)), 1075), fill='#76d9f3')
        proc.stdin.write(im.tobytes())
finally:
    proc.stdin.close()
assert proc.wait() == 0
print(json.dumps({'duration_seconds': duration, 'frames': math.ceil(duration * fps), 'path': str(target)}))

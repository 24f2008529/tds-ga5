import json
from collections import deque

M = json.load(open("maze.json"))
W, H = M["width"], M["height"]
mask = M["openMask"]
sx, sy = M["start"]; ex, ey = M["end"]

DIRS = [("U",0,-1,1), ("R",1,0,2), ("D",0,1,4), ("L",-1,0,8)]  # letter, dx, dy, bit

start, end = (sx, sy), (ex, ey)
prev = {start: None}
q = deque([start])
while q:
    x, y = q.popleft()
    if (x, y) == end:
        break
    for letter, dx, dy, bit in DIRS:
        if mask[y][x] & bit:                 # this direction is open
            nx, ny = x+dx, y+dy
            if (nx, ny) not in prev:
                prev[(nx, ny)] = (x, y, letter)
                q.append((nx, ny))

# walk the parent chain back to build the move string
path = []
cur = end
while prev[cur] is not None:
    px, py, letter = prev[cur]
    path.append(letter)
    cur = (px, py)
print("".join(reversed(path)))

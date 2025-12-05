# RedHunllef Shuffle Wager Leaderboard

A small Flask app that shows a **live Shuffle.com wager race** for RedHunllef:
top-10 wagerers, prizes per placement, live Kick status, and a modern,
responsive UI.

The backend talks to Shuffle and Kick, the frontend is just
`index.html + style.css + script.js`.

---

## Project structure

```text
.
├─ wager_backend.py      # Flask app, Shuffle/Kick integration, caching, logging
├─ requirements.txt      # Python dependencies
├─ README.md
├─ templates/
│  ├─ index.html         # Main leaderboard page
│  └─ 404.html           # Custom 404 page
└─ static/
   ├─ style.css          # Layout + visual styles
   ├─ script.js          # Leaderboard logic + API calls
   ├─ redlogo.png        # Bouncing logo in the header
   └─ redlogo.ico        # Favicon

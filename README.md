# RedHunllef Shuffle Wager Leaderboard

A streamlined web app that displays **live wager placements** for Shuffle, featuring RedHunllef.  
The app automatically updates placements, shows prizes, and highlights the top 10 wagerers in a modern, mobile-friendly interface.  

---

## ✨ Features
- **Top 10 Wager Leaderboard** with podium for top 3 and inline row for 4–10.  
- **Automatic Updates** every 60 seconds — no refresh required.  
- **Privacy-Friendly**: usernames are shortened automatically.  
- **Streamer Status**: Displays if RedHunllef is **LIVE NOW!** with viewer count.  
- **Responsive Design**: Works on desktop and mobile devices.  
- **Detailed Console Logging** for saves, updates, and requests (for monitoring/debugging).  

---

## ⚙️ Configurable Settings

### 1. Wager Race Start & End Times
In **`wager_backend.py`**, locate this section near the top:
```python
# Epoch times (Unix timestamps)
WAGER_START = 1755662460  # Example: Start of race
WAGER_END   = 1756871940  # Example: End of race
````

* These are **epoch times in seconds** (Unix timestamps).
* You can generate them easily at [https://www.epochconverter.com](https://www.epochconverter.com).
* Example:

  * Start: **August 20, 2025 00:01 AM EST** → `1755662460`
  * End: **September 2, 2025 11:59 PM EST** → `1756871940`

When you update these values, the leaderboard will automatically respect the new window.

---

### 2. Countdown Timer on the Frontend

In **`index.html`**, look for:

```javascript
const targetDate = new Date('2025-09-02T23:59:59-04:00');
```

* This controls the **countdown timer** displayed on the site.
* To reset for a new race, simply update this date/time string.
* Example: if your next race ends **October 31, 2025 at 11:59 PM EST**, change it to:

```javascript
const targetDate = new Date('2025-10-31T23:59:59-04:00');
```

---

### 3. Update Interval (Cache Refresh)

By default, the backend updates every 60 seconds:

```python
scheduler.add_job(update_cache, "interval", seconds=60, id="cache_update")
```

* Change `seconds=60` if you want faster or slower refreshes.

---

### 4. Streamer Channel

The Kick channel being tracked is currently set to:

```python
KICK_CHANNEL = "redhunllef"
```

Change this if you want to track a different streamer.

---

## 🚀 Running the App

### 1. Install Dependencies

Run the following in your project folder:

```bash
pip install flask requests apscheduler
```

### 2. Start the Backend

```bash
python wager_backend.py
```

### 3. Visit the Webpage

Once the server is running, open your browser at:

```
http://localhost:5000
```

---

## 🔄 Resetting for a New Wager Race

When a new race starts:

1. Update `WAGER_START` and `WAGER_END` in **`wager_backend.py`**.
2. Update `targetDate` in **`index.html`**.
3. Restart the backend with:

   ```bash
   python wager_backend.py
   ```

# HackStone

## Setup
1. Create and activate a virtual environment (optional but recommended).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Run the dashboard
```bash
streamlit run app.py
```

The dashboard expects a live events API at `http://127.0.0.1:8000/events?limit=100`.
Start your backend before launching Streamlit so data loads correctly.

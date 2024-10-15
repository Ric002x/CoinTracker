from app.base.run import app
from app.base.utils import start_schedule

if __name__ == "__main__":
    start_schedule()
    app.run(host='0.0.0.0', port=5000, debug=False)

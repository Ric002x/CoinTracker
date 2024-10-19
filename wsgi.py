from app import create_app, db
from app.utils import start_schedule

app = create_app()

with app.app_context():
    db.create_all()
    start_schedule()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=False)

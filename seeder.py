from app import app, db, User, Job, Profile
from werkzeug.security import generate_password_hash
from datetime import datetime

def seed_data():
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Database Reset.")

        # 1. Create SUPER ADMIN
        admin = User(
            username="Super Admin",
            email="admin@khelo.com",
            password=generate_password_hash("admin123"),
            role="admin"
        )
        db.session.add(admin)
        print("Super Admin created (admin@khelo.com / admin123)")

        # 2. Create Employers
        employers = [
            {"name": "Mumbai Cricket Association", "email": "mca@test.com"},
            {"name": "Bangalore FC Academy", "email": "bfc@test.com"}
        ]
        
        emp_objs = []
        for emp in employers:
            user = User(
                username=emp["name"], 
                email=emp["email"], 
                password=generate_password_hash("123456"),
                role="employer"
            )
            db.session.add(user)
            emp_objs.append(user)
        
        db.session.commit()

        # 3. Create Jobs
        jobs_data = [
            {"title": "Head Cricket Coach", "sport": "Cricket", "loc": "Mumbai", "lat": 18.9389, "lng": 72.8258, "sal": "60k", "desc": "Ranji exp needed.", "emp": emp_objs[0]},
            {"title": "Senior Football Coach", "sport": "Football", "loc": "Bangalore", "lat": 12.9698, "lng": 77.5958, "sal": "80k", "desc": "AFC B License.", "emp": emp_objs[1]}
        ]

        for j in jobs_data:
            job = Job(
                employer_id=j["emp"].id,
                title=j["title"],
                sport=j["sport"],
                location=j["loc"],
                lat=j["lat"],
                lng=j["lng"],
                description=j["desc"],
                salary_range=j["sal"],
                posted_date=datetime.utcnow()
            )
            db.session.add(job)

        # 4. Create Coaches (One Verified, One Unverified)
        
        # Verified Coach
        c1 = User(username="Rahul Dravid", email="coach1@test.com", password=generate_password_hash("123456"), role="coach")
        db.session.add(c1)
        db.session.commit()
        p1 = Profile(user_id=c1.id, full_name="Rahul Dravid", sport="Cricket", experience_years=20, is_verified=True, bio="Legend.")
        db.session.add(p1)

        # Pending Coach (Has proof but not verified)
        c2 = User(username="Newbie Coach", email="coach2@test.com", password=generate_password_hash("123456"), role="coach")
        db.session.add(c2)
        db.session.commit()
        p2 = Profile(user_id=c2.id, full_name="Newbie Coach", sport="Football", experience_years=2, is_verified=False, cert_proof_path="dummy.pdf", bio="Hardworking.")
        db.session.add(p2)

        db.session.commit()
        print("Seeding Complete!")

if __name__ == "__main__":
    seed_data()
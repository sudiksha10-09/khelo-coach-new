import app
from app import db, User, Profile, Job, Application, Review
from werkzeug.security import generate_password_hash
from datetime import datetime
import random

def run_seeds():
    with app.app.app_context():

        print("🌱 Seeding database...")

        # -----------------------
        # USERS
        # -----------------------
        admin = User(
            username="Admin",
            email="admin@khelo.com",
            role="admin",
            password=generate_password_hash("admin123")
        )

        employer = User(
            username="Mumbai Academy",
            email="academy@khelo.com",
            role="employer",
            password=generate_password_hash("academy123")
        )

        coach1 = User(
            username="Rahul Coach",
            email="rahul@khelo.com",
            role="coach",
            password=generate_password_hash("coach123")
        )

        coach2 = User(
            username="Amit Coach",
            email="amit@khelo.com",
            role="coach",
            password=generate_password_hash("coach123")
        )

        db.session.add_all([admin, employer, coach1, coach2])
        db.session.commit()

        # -----------------------
        # PROFILES
        # -----------------------
        profiles = [
            Profile(
                user_id=coach1.id,
                full_name="Rahul Sharma",
                sport="Cricket",
                experience_years=5,
                city="Mumbai",
                certifications="BCCI Level 1",
                bio="Experienced cricket coach for junior & senior teams.",
                is_verified=True
            ),
            Profile(
                user_id=coach2.id,
                full_name="Amit Verma",
                sport="Football",
                experience_years=3,
                city="Pune",
                certifications="AIFF C License",
                bio="Youth football coach with academy experience.",
                is_verified=False
            )
        ]

        db.session.add_all(profiles)
        db.session.commit()

        # -----------------------
        # JOBS
        # -----------------------
        jobs = [
            Job(
                employer_id=employer.id,
                title="Cricket Head Coach",
                sport="Cricket",
                location="Mumbai",
                description="Looking for an experienced cricket coach.",
                requirements="BCCI certification, 3+ years experience",
                salary_range="30000 - 50000",
                job_type="Full Time",
                is_active=True
            ),
            Job(
                employer_id=employer.id,
                title="Football Assistant Coach",
                sport="Football",
                location="Pune",
                description="Assist senior coach for youth teams.",
                requirements="AIFF license preferred",
                salary_range="15000 - 25000",
                job_type="Part Time",
                is_active=True
            )
        ]

        db.session.add_all(jobs)
        db.session.commit()

        # -----------------------
        # APPLICATIONS
        # -----------------------
        app1 = Application(
            job_id=jobs[0].id,
            user_id=coach1.id,
            match_score=90,
            match_reasons="Sport Match (+40) | Experience > 2y (+30) | Verified Badge (+20)",
            status="Applied"
        )

        app2 = Application(
            job_id=jobs[1].id,
            user_id=coach2.id,
            match_score=70,
            match_reasons="Sport Match (+40) | Experience > 2y (+30)",
            status="Interview"
        )

        db.session.add_all([app1, app2])
        db.session.commit()

        # -----------------------
        # REVIEWS
        # -----------------------
        review = Review(
            profile_id=profiles[0].id,
            reviewer_id=employer.id,
            rating=5,
            comment="Excellent coach with great discipline."
        )

        db.session.add(review)
        db.session.commit()

        print("✅ Seeding completed successfully!")

if __name__ == "__main__":
    run_seeds()

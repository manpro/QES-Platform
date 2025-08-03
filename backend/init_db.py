"""
Database initialization script.
"""

import sys
import os

# Add backend to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import create_tables, engine
from models import Base

def init_database():
    """Initialize database with all tables."""
    print("Creating database tables...")
    
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
        
        # Print created tables
        inspector = engine.dialect.get_table_names
        tables = Base.metadata.tables.keys()
        print(f"📋 Created tables: {', '.join(tables)}")
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False
    
    return True

if __name__ == "__main__":
    init_database()
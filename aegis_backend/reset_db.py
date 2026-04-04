import asyncio
import csv
import os
from sqlalchemy import insert
from app.core.database import engine, Base
from app.models.orm import Node, SystemLog, SchemaConfig, AnomalyRecord, QuarantineLog

async def reset_database():
    print(" [!] RESETTING AEGIS CORE DATABASE...")
    async with engine.begin() as conn:
        # Drop all existing tables
        await conn.run_sync(Base.metadata.drop_all)
        print(" [+] Tables dropped.")
        # Recreate all tables
        await conn.run_sync(Base.metadata.create_all)
        print(" [+] Tables recreated (Clean Schema).")
    
    # Seeding
    async with engine.begin() as conn:
        # 1. Seed Nodes
        nodes_path = "data/node_registry.csv"
        if os.path.exists(nodes_path):
            with open(nodes_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                nodes_to_insert = []
                for row in reader:
                    nodes_to_insert.append({
                        "node_uuid": int(row['node_uuid']),
                        "user_agent": row['user_agent'],
                        "serial_number": f"SN-{1000 + int(row['node_uuid'])}", # placeholder decoding logic
                        "is_infected": row['is_infected'].lower() == 'true'
                    })
                if nodes_to_insert:
                    await conn.execute(insert(Node), nodes_to_insert)
            print(f" [+] Seeded {len(nodes_to_insert)} nodes.")

        # 2. Seed Schema Config
        schema_path = "data/schema_config.csv"
        if os.path.exists(schema_path):
            with open(schema_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                schemas_to_insert = []
                for row in reader:
                    schemas_to_insert.append({
                        "version": int(row['version']),
                        "time_start": int(row['time_start']),
                        "active_column": row['active_column']
                    })
                if schemas_to_insert:
                    await conn.execute(insert(SchemaConfig), schemas_to_insert)
            print(f" [+] Seeded {len(schemas_to_insert)} schema configurations.")
    
    print(" [+] AEGIS DATABASE IS PRISTINE AND SEEDED.")

if __name__ == "__main__":
    asyncio.run(reset_database())
import psycopg2

conn = psycopg2.connect("postgresql://cortexsoc:cortexsoc_secret@127.0.0.1:5432/cortexsoc")
cur = conn.cursor()

cur.execute("ALTER TYPE incident_status ADD VALUE IF NOT EXISTS 'approved'")
cur.execute("ALTER TYPE incident_status ADD VALUE IF NOT EXISTS 'rejected'")
conn.commit()

cur.execute(
    "SELECT enumlabel FROM pg_enum WHERE enumtypid="
    "(SELECT oid FROM pg_type WHERE typname=%s) ORDER BY enumsortorder",
    ("incident_status",),
)
print([r[0] for r in cur.fetchall()])
conn.close()

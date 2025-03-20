from app import app, db, User, Appointment, SupplyOrder, Availability

def display_database():
    print("\n=== Users ===")
    print("ID | Username | Role | Email | Approved")
    print("-" * 50)
    users = User.query.all()
    for user in users:
        print(f"{user.id} | {user.username} | {user.role} | {user.email} | {user.approved}")

    print("\n=== Appointments ===")
    print("ID | Patient | Doctor | Date | Status | Insurance Status")
    print("-" * 60)
    appointments = Appointment.query.all()
    for apt in appointments:
        print(f"{apt.id} | {apt.patient_username} | {apt.doctor_username} | {apt.date} | {apt.status} | {apt.insurance_status}")

    print("\n=== Supply Orders ===")
    print("ID | Supplier | Item | Quantity | Order Date | Status")
    print("-" * 60)
    orders = SupplyOrder.query.all()
    for order in orders:
        print(f"{order.id} | {order.supplier_username} | {order.item} | {order.quantity} | {order.order_date} | {order.status}")

    print("\n=== Doctor Availability ===")
    print("ID | Doctor | Date | Slots")
    print("-" * 40)
    availability = Availability.query.all()
    for avail in availability:
        print(f"{avail.id} | {avail.doctor_username} | {avail.date} | {avail.slots}")

if __name__ == "__main__":
    with app.app_context():
        display_database()
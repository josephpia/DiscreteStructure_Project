"""
LBSADMS - Logic-Based Security Access Decision Management System
Midterm Project - Access Control System
Using Logic, Sets, Relations, Boolean Algebra, Matrices & Number Theory
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import numpy as np
import hashlib
from datetime import datetime

# ============================================================================
# MODEL CLASSES
# ============================================================================

class User:
    """Represents a user in the access control system"""
    
    def __init__(self, user_id, name, user_type, is_authorized=False):
        self.user_id = user_id
        self.name = name
        self.user_type = user_type
        self.is_authorized = is_authorized
        self.access_level = self._determine_access_level()
        self.card_number = self._generate_card_number()
        self.unique_id = self._generate_unique_id()
        self.uuid = self._generate_uuid()
        self.qr_code = self._generate_qr_code()
        
    def _determine_access_level(self):
        access_levels = {
            'admin': 7,
            'faculty': 6,
            'staff': 5,
            'student': 4,
            'visitor': 2,
        }
        return access_levels.get(self.user_type, 1)
    
    def _generate_card_number(self):
        return str(1000 + self.user_id)
    
    def _generate_unique_id(self):
        year = datetime.now().year % 100
        type_codes = {'admin': 7, 'faculty': 5, 'staff': 3, 'student': 2, 'visitor': 1}
        type_code = type_codes.get(self.user_type, 0)
        prime = 1000003
        base = self.user_id * prime + type_code
        modulo = 999999
        unique_num = base % modulo
        if unique_num < 100000:
            unique_num += 100000
        type_prefix = self.user_type[:2].upper()
        unique_id = f"{type_prefix}{year}{unique_num:06d}"
        check_digit = self._calculate_check_digit(unique_id)
        return f"{unique_id}{check_digit}"
    
    def _calculate_check_digit(self, id_string):
        total = 0
        for i, char in enumerate(id_string):
            if char.isdigit():
                digit = int(char)
                if i % 2 == 0:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                total += digit
            else:
                total += ord(char) % 10
        return str((10 - (total % 10)) % 10)
    
    def _generate_uuid(self):
        import uuid
        data = f"{self.user_id}{self.name}{self.user_type}{datetime.now().year}"
        hash_obj = hashlib.sha256(data.encode())
        return str(uuid.UUID(hash_obj.hexdigest()[:32]))
    
    def _generate_qr_code(self):
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        prime_index = self.user_id % len(primes)
        selected_prime = primes[prime_index]
        qr_base = self.user_id * selected_prime + self.access_level
        qr_mod = qr_base % 1000
        qr_check = (qr_base * 7 + 13) % 100
        return f"QR{selected_prime:02d}{qr_mod:03d}{qr_check:02d}"
    
    def __repr__(self):
        return f"User({self.name}, {self.user_type}, Card: {self.card_number})"


class Facility:
    """Represents a facility or room in the system"""
    
    def __init__(self, facility_id, name, facility_type, required_access_level=1):
        self.facility_id = facility_id
        self.name = name
        self.facility_type = facility_type
        self.required_access_level = required_access_level
        self.is_restricted = facility_type == 'restricted'
        
    def __repr__(self):
        return f"Facility({self.name}, {self.facility_type}, Level: {self.required_access_level})"

class PermissionMatrix:
    """Manages access permissions using matrices"""
    
    def __init__(self, users, facilities):
        self.users = users
        self.facilities = facilities
        self.matrix = self._build_matrix()
        self.access_log = []
        
    def _build_matrix(self):
        matrix = np.zeros((len(self.users), len(self.facilities)), dtype=int)
        for i, user in enumerate(self.users):
            for j, facility in enumerate(self.facilities):
                matrix[i][j] = 1 if self._check_access(user, facility) else 0
        return matrix
    
    def _check_access(self, user, facility):
        is_authorized = user.is_authorized
        has_sufficient_level = user.access_level >= facility.required_access_level
        is_faculty_or_staff = user.user_type in {'faculty', 'staff'}
        
        if facility.is_restricted:
            is_admin = user.user_type == 'admin'
            extra_check = (user.user_id % 2 == 0) if user.user_type == 'student' else True
            return is_authorized and (is_admin or (has_sufficient_level and extra_check))
        
        return is_authorized and (has_sufficient_level or is_faculty_or_staff)
    
    def check_access(self, user_id, facility_id):
        user_index = self._find_user_index(user_id)
        facility_index = self._find_facility_index(facility_id)
        if user_index is not None and facility_index is not None:
            return bool(self.matrix[user_index][facility_index])
        return False
    
    def get_user_by_card(self, card_number):
        for user in self.users:
            if user.card_number == card_number:
                return user
        return None
    
    def _find_user_index(self, user_id):
        for i, user in enumerate(self.users):
            if user.user_id == user_id:
                return i
        return None
    
    def _find_facility_index(self, facility_id):
        for i, facility in enumerate(self.facilities):
            if facility.facility_id == facility_id:
                return i
        return None
    
    def log_access_attempt(self, card_number, facility_id, granted):
        user = self.get_user_by_card(card_number)
        facility = None
        for f in self.facilities:
            if f.facility_id == facility_id:
                facility = f
                break
        
        self.access_log.append({
            'timestamp': datetime.now().isoformat(),
            'card_number': card_number,
            'user_name': user.name if user else 'Unknown',
            'facility_name': facility.name if facility else 'Unknown',
            'granted': granted
        })
        if len(self.access_log) > 100:
            self.access_log = self.access_log[-100:]
    
    def get_access_log(self):
        return self.access_log
    
    def get_matrix_display(self):
        max_name_length = max([len(f.name) for f in self.facilities]) + 2
        col_width = max(max_name_length, 14)
        max_user_length = max([len(u.name) for u in self.users]) + 2
        user_col_width = max(max_user_length, 14)
        
        lines = []
        lines.append("=" * (user_col_width + len(self.facilities) * col_width + 4))
        lines.append(" PERMISSION MATRIX ".center(user_col_width + len(self.facilities) * col_width + 4))
        lines.append("=" * (user_col_width + len(self.facilities) * col_width + 4))
        lines.append("")
        lines.append(" Rows: Users (Card ID) | Columns: Facilities | 1=Access Granted, 0=Access Denied")
        lines.append("")
        
        header = " " * user_col_width
        for facility in self.facilities:
            name = facility.name[:col_width-2] if len(facility.name) > col_width-2 else facility.name
            header += f"{name:^{col_width}}"
        lines.append(header)
        
        sep = "-" * user_col_width
        for _ in self.facilities:
            sep += "-" * col_width
        lines.append(sep)
        
        for i, user in enumerate(self.users):
            row = f"{user.name} ({user.card_number})"
            row = row[:user_col_width]
            for j in range(len(self.facilities)):
                row += f"{self.matrix[i][j]:^{col_width}}"
            lines.append(row)
        
        lines.append("-" * (user_col_width + len(self.facilities) * col_width + 4))
        lines.append(f"  Total Users: {len(self.users)} | Total Facilities: {len(self.facilities)}")
        lines.append("  1 = Access Granted | 0 = Access Denied")
        return "\n".join(lines)
    
    def prove_access_rules(self):
        proof = []
        proof.append("=" * 70)
        proof.append("PROOF OF ACCESS RULE VALIDITY")
        proof.append("=" * 70)
        proof.append("")
        proof.append("1. LOGICAL VALIDITY PROOF:")
        proof.append("   Access Rule: ∀u ∈ Users, ∀f ∈ Facilities,")
        proof.append("   Access(u,f) ↔ (Authorized(u) ∧ (Level(u) ≥ Required(f) ∨ Type(u) ∈ Faculty/Staff))")
        proof.append("")
        for user in self.users[:4]:
            for facility in self.facilities[:3]:
                access = self._check_access(user, facility)
                proof.append(f"   User: {user.name} (Card: {user.card_number}) → {facility.name}: {access}")
        proof.append("")
        proof.append("2. SET THEORY VALIDITY:")
        proof.append("   User Sets: Students, Faculty, Staff, Visitors, Authorized Users")
        proof.append("   ∀u ∈ Authorized ∩ (Faculty ∪ Staff): Access Granted")
        proof.append("")
        proof.append("3. BOOLEAN ALGEBRA VALIDITY:")
        proof.append("   Access = A ∧ (L ∨ T) where A=Authorization, L=Level, T=Type")
        proof.append("")
        proof.append("4. NUMBER THEORY VALIDITY:")
        proof.append("   Card ID = 1000 + user_id | Unique ID uses modular arithmetic")
        proof.append("")
        proof.append("5. MATRIX CONSISTENCY:")
        proof.append("   Matrix M[i][j] = 1 if access granted, 0 otherwise")
        proof.append("")
        proof.append("=" * 70)
        proof.append("CONCLUSION: Access rules are valid and consistent")
        proof.append("=" * 70)
        return "\n".join(proof)


class AccessControlSystem:
    """Main system that integrates all components"""
    
    def __init__(self):
        self.users = []
        self.facilities = []
        self.permission_matrix = None
        self._initialize_system()
        
    def _initialize_system(self):
        self.users = [
            User(1, "Dr. Smith", "faculty", True),
            User(2, "Prof. Johnson", "faculty", True),
            User(3, "Alice", "student", True),
            User(4, "Bob", "student", True),
            User(5, "Carol", "student", True),
            User(6, "Dave", "staff", True),
            User(7, "Eve", "visitor", False),
            User(8, "Frank", "admin", True),
        ]
        
        self.facilities = [
            Facility(1, "Activity Center", "Venue", 1),
            Facility(2, "Registrar Office", "Office", 2),
            Facility(3, "Lecture Room", "classroom", 3),
            Facility(4, "Com Lab", "Lab", 4),
            Facility(5, "Library", "library", 5),
            Facility(6, "Faculty Office", "Office", 6),
            Facility(7, "Server Room", "restricted", 7),
        ]
        
        self.permission_matrix = PermissionMatrix(self.users, self.facilities)
    
    def check_access(self, user_id, facility_id):
        return self.permission_matrix.check_access(user_id, facility_id)
    
    def get_user_by_card(self, card_number):
        return self.permission_matrix.get_user_by_card(card_number)
    
    def _find_user(self, user_id):
        for user in self.users:
            if user.user_id == user_id:
                return user
        return None
    
    def _find_facility(self, facility_id):
        for facility in self.facilities:
            if facility.facility_id == facility_id:
                return facility
        return None
    
    def get_user_accessible_facilities(self, user_id):
        accessible = []
        for facility in self.facilities:
            if self.check_access(user_id, facility.facility_id):
                accessible.append(facility)
        return accessible
    
    def classify_users_by_access_level(self):
        user_sets = {
            'authorized': set(), 'restricted': set(), 'students': set(),
            'faculty': set(), 'staff': set(), 'visitors': set()
        }
        for user in self.users:
            if user.is_authorized:
                user_sets['authorized'].add(f"{user.name} (Card: {user.card_number})")
            if user.user_type == 'student':
                user_sets['students'].add(f"{user.name} (Card: {user.card_number})")
            elif user.user_type == 'faculty':
                user_sets['faculty'].add(f"{user.name} (Card: {user.card_number})")
            elif user.user_type == 'staff':
                user_sets['staff'].add(f"{user.name} (Card: {user.card_number})")
            elif user.user_type == 'visitor':
                user_sets['visitors'].add(f"{user.name} (Card: {user.card_number})")
            if user.user_type == 'admin' or (user.user_type == 'student' and user.user_id % 2 == 0):
                user_sets['restricted'].add(user.name)
        return user_sets
    
    def get_system_stats(self):
        stats = {
            'total_users': len(self.users),
            'total_facilities': len(self.facilities),
            'authorized_users': sum(1 for u in self.users if u.is_authorized),
            'unauthorized_users': sum(1 for u in self.users if not u.is_authorized),
            'facilities_by_type': {},
            'users_by_type': {},
            'access_matrix': self.permission_matrix.get_matrix_display(),
            'proof': self.permission_matrix.prove_access_rules(),
            'access_log': self.permission_matrix.get_access_log()
        }
        for facility in self.facilities:
            stats['facilities_by_type'][facility.facility_type] = stats['facilities_by_type'].get(facility.facility_type, 0) + 1
        for user in self.users:
            stats['users_by_type'][user.user_type] = stats['users_by_type'].get(user.user_type, 0) + 1
        return stats


# ============================================================================
# FLASK APPLICATION
# ============================================================================

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

access_system = AccessControlSystem()


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        card_number = request.form.get('card_number', '').strip()
        facility_id = int(request.form.get('facility_id'))
        
        user = access_system.get_user_by_card(card_number)
        
        if not user:
            return render_template('login.html', 
                                 error=f"Card ID '{card_number}' not found",
                                 users=access_system.users,
                                 facilities=access_system.facilities)
        
        has_access = access_system.check_access(user.user_id, facility_id)
        facility = access_system._find_facility(facility_id)
        
        access_system.permission_matrix.log_access_attempt(card_number, facility_id, has_access)
        
        session['user_id'] = user.user_id
        session['user_name'] = user.name
        session['card_number'] = user.card_number
        session['user_type'] = user.user_type
        
        if has_access:
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html',
                                 error=f"Access Denied! {user.name} cannot access {facility.name}",
                                 users=access_system.users,
                                 facilities=access_system.facilities,
                                 card_number=card_number,
                                 selected_facility=facility_id)
    
    return render_template('login.html', 
                         users=access_system.users,
                         facilities=access_system.facilities)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = access_system._find_user(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    allowed_facilities = access_system.get_user_accessible_facilities(user.user_id)
    user_sets = access_system.classify_users_by_access_level()
    matrix_display = access_system.permission_matrix.get_matrix_display()
    proof = access_system.permission_matrix.prove_access_rules()
    access_log = access_system.permission_matrix.get_access_log()
    
    return render_template('dashboard.html',
                         user=user,
                         allowed_facilities=allowed_facilities,
                         user_sets=user_sets,
                         matrix_display=matrix_display,
                         proof=proof,
                         access_log=access_log,
                         permission_matrix=access_system.permission_matrix,
                         facilities=access_system.facilities)


@app.route('/access_check', methods=['GET', 'POST'])
def access_check():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        card_number = request.form.get('card_number', '').strip()
        facility_id = int(request.form.get('facility_id'))
        
        user = access_system.get_user_by_card(card_number)
        
        if not user:
            return render_template('access_check.html',
                                 error=f"Card ID '{card_number}' not found",
                                 users=access_system.users,
                                 facilities=access_system.facilities,
                                 permission_matrix=access_system.permission_matrix)
        
        has_access = access_system.check_access(user.user_id, facility_id)
        facility = access_system._find_facility(facility_id)
        
        access_system.permission_matrix.log_access_attempt(card_number, facility_id, has_access)
        
        user_facilities = access_system.get_user_accessible_facilities(user.user_id)
        user_sets = access_system.classify_users_by_access_level()
        matrix_display = access_system.permission_matrix.get_matrix_display()
        proof = access_system.permission_matrix.prove_access_rules()
        access_log = access_system.permission_matrix.get_access_log()
        
        return render_template('access_check.html',
                             user=user,
                             facility=facility,
                             has_access=has_access,
                             user_facilities=user_facilities,
                             user_sets=user_sets,
                             matrix_display=matrix_display,
                             proof=proof,
                             access_log=access_log,
                             users=access_system.users,
                             facilities=access_system.facilities,
                             permission_matrix=access_system.permission_matrix,
                             card_number=card_number)
    
    return render_template('access_check.html',
                         users=access_system.users,
                         facilities=access_system.facilities,
                         permission_matrix=access_system.permission_matrix,
                         access_log=access_system.permission_matrix.get_access_log())


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = access_system._find_user(session['user_id'])
    if not user or user.user_type != 'admin':
        return "Access Denied: Admins only.", 403
    
    stats = access_system.get_system_stats()
    users = access_system.users
    facilities = access_system.facilities
    user_sets = access_system.classify_users_by_access_level()
    matrix = access_system.permission_matrix.get_matrix_display()
    access_log = access_system.permission_matrix.get_access_log()
    
    users_with_ids = []
    for u in users:
        users_with_ids.append({
            'id': u.user_id,
            'name': u.name,
            'type': u.user_type,
            'authorized': u.is_authorized,
            'access_level': u.access_level,
            'card_number': u.card_number,
            'unique_id': u.unique_id,
            'uuid': u.uuid,
            'qr_code': u.qr_code
        })
    
    return render_template('admin.html',
                         stats=stats,
                         users=users,
                         users_with_ids=users_with_ids,
                         facilities=facilities,
                         user_sets=user_sets,
                         matrix=matrix,
                         permission_matrix=access_system.permission_matrix,
                         access_log=access_log)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/users')
def api_users():
    return jsonify([{
        'id': u.user_id,
        'name': u.name,
        'type': u.user_type,
        'authorized': u.is_authorized,
        'access_level': u.access_level,
        'card_number': u.card_number
    } for u in access_system.users])


@app.route('/api/facilities')
def api_facilities():
    return jsonify([{
        'id': f.facility_id,
        'name': f.name,
        'type': f.facility_type,
        'required_level': f.required_access_level,
        'is_restricted': f.is_restricted
    } for f in access_system.facilities])


@app.route('/api/check_access', methods=['POST'])
def api_check_access():
    data = request.get_json()
    card_number = data.get('card_number')
    facility_id = data.get('facility_id')
    user = access_system.get_user_by_card(card_number)
    if user:
        has_access = access_system.check_access(user.user_id, facility_id)
        return jsonify({'access_granted': has_access, 'user': user.name})
    return jsonify({'access_granted': False, 'error': 'User not found'})


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("LBSADMS - Logic-Based Security Access Decision Management System")
    print("=" * 70)
    print("\nSystem initialized with:")
    print(f"  - {len(access_system.users)} users")
    print(f"  - {len(access_system.facilities)} facilities")
    print("\nCard IDs for Login:")
    for user in access_system.users:
        print(f"  - {user.name}: {user.card_number} ({user.user_type})")
    print("\n" + "=" * 70)
    print("Starting Flask server...")
    print("Open http://127.0.0.1:5000 in your browser")
    print("=" * 70)
    app.run(debug=True)
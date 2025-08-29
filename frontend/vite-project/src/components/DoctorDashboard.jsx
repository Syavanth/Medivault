import { useState, useEffect } from 'react';
import { Users, ClipboardList, Calendar, Shield, Bell, Plus, Check, X, User, ChevronDown, LogOut, FileText } from "lucide-react";

export default function DoctorDashboard() {
  const [currentUser, setCurrentUser] = useState({
    username: '',
    name: '',
    role: 'doctor'
  });

  const [patients, setPatients] = useState([]);
  const [appointments, setAppointments] = useState([]);
  const [prescriptions, setPrescriptions] = useState([]);
  const [activeTab, setActiveTab] = useState('prescriptions');
  const [showUserDropdown, setShowUserDropdown] = useState(false);
  const [showPrescriptionForm, setShowPrescriptionForm] = useState(false);
  const [prescriptionForm, setPrescriptionForm] = useState({
    patientId: '',
    diagnosis: '',
    date: new Date().toISOString().split('T')[0],
    medicines: [{ name: '', dosage: '', instructions: '' }]
  });

  const [eligiblePatients, setEligiblePatients] = useState([]);

  const API_BASE_URL = 'http://localhost:5000/api';

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const token = localStorage.getItem('token');
        const user = JSON.parse(localStorage.getItem('user'));
        if (user) {
          setCurrentUser({
            username: user.username,
            name: user.name,
            role: user.role
          });
        }

        const response = await fetch(`${API_BASE_URL}/doctor/dashboard`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (!response.ok) {
          throw new Error('Failed to fetch dashboard data');
        }

        const data = await response.json();
        setPatients(data.patients || []);
        setAppointments(data.appointments || []);
        setPrescriptions(data.prescriptions || []);

        // Fetch eligible patients for prescriptions
        const patientsResponse = await fetch(`${API_BASE_URL}/doctor/eligible-patients`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (!patientsResponse.ok) {
          throw new Error('Failed to fetch eligible patients');
        }

        const patientsData = await patientsResponse.json();
        setEligiblePatients(patientsData);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };

    fetchDashboardData();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  const handleAddMedicine = () => {
    setPrescriptionForm(prev => ({
      ...prev,
      medicines: [...prev.medicines, { name: '', dosage: '', instructions: '' }]
    }));
  };

  const handleRemoveMedicine = (index) => {
    setPrescriptionForm(prev => ({
      ...prev,
      medicines: prev.medicines.filter((_, i) => i !== index)
    }));
  };

  const handleMedicineChange = (index, field, value) => {
    setPrescriptionForm(prev => ({
      ...prev,
      medicines: prev.medicines.map((medicine, i) => 
        i === index ? { ...medicine, [field]: value } : medicine
      )
    }));
  };

  const handleSubmitPrescription = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/doctor/prescriptions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(prescriptionForm)
      });

      if (!response.ok) {
        throw new Error('Failed to create prescription');
      }

      setPrescriptionForm({
        patientId: '',
        diagnosis: '',
        date: new Date().toISOString().split('T')[0],
        medicines: [{ name: '', dosage: '', instructions: '' }]
      });
      setShowPrescriptionForm(false);
      alert('Prescription created successfully!');
    } catch (error) {
      console.error('Error creating prescription:', error);
      alert('Failed to create prescription');
    }
  };

  const handleCompleteAppointment = async (appointmentId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/doctor/appointments/${appointmentId}/complete`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to complete appointment');
      }

      // Update local state
      setAppointments(appointments.map(appt => 
        appt.id === appointmentId ? { ...appt, status: 'completed' } : appt
      ));
      alert('Appointment marked as completed!');
    } catch (error) {
      console.error('Error completing appointment:', error);
      alert('Failed to complete appointment');
    }
  };

  const handleCancelAppointment = async (appointmentId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/doctor/appointments/${appointmentId}/cancel`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Failed to cancel appointment');
      }

      // Update local state
      setAppointments(appointments.map(appt => 
        appt.id === appointmentId ? { ...appt, status: 'cancelled' } : appt
      ));
      alert('Appointment cancelled successfully!');
    } catch (error) {
      console.error('Error cancelling appointment:', error);
      alert('Failed to cancel appointment');
    }
  };

  const handleRequestAccess = async (patientId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/doctor/request-access`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          patient_id: patientId
        })
      });

      if (!response.ok) {
        throw new Error('Failed to request access');
      }

      alert('Access request sent successfully!');
      // Refresh the patients list to update access status
      fetchPatients();
    } catch (error) {
      console.error('Error requesting access:', error);
      alert('Failed to request access. Please try again.');
    }
  };

  const handleViewPatientData = async (patientId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/doctor/patient/${patientId}/data`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch patient data');
      }

      const data = await response.json();
      setSelectedPatient(data);
      setShowPatientDataModal(true);
    } catch (error) {
      console.error('Error fetching patient data:', error);
      alert('Failed to fetch patient data. Please try again.');
    }
  };

  return (
    <div className="min-h-screen bg-white text-black">
      {/* Header */}
      {/* Patients List Section */}
      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Patients</h2>
        {patients.length === 0 ? (
          <p className="text-gray-500">No patients found</p>
        ) : (
          <ul className="divide-y divide-gray-200">
            {patients.map((p) => (
              <li key={p.id || p.user_id} className="py-2 flex flex-col">
                <span className="font-medium">{p.name}</span>
                <span className="text-sm text-gray-500">{p.username || ''}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      <header className="bg-teal-600 text-white shadow-md">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6" />
            <h1 className="text-xl font-bold">MediVault - Doctor Portal</h1>
          </div>
          <div className="flex items-center space-x-4">
            <div className="relative">
              <div className="flex items-center space-x-2">
                <span className="text-white">{currentUser.name}</span>
                <button
                  onClick={() => setShowUserDropdown(!showUserDropdown)}
                  className="flex items-center space-x-2 text-white hover:bg-teal-700 px-3 py-2 rounded-md"
                >
                  <User className="h-4 w-4" />
                  <ChevronDown className="h-4 w-4" />
                </button>
              </div>
              {showUserDropdown && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50">
                  <button
                    onClick={handleLogout}
                    className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 flex items-center"
                  >
                    <LogOut className="h-4 w-4 mr-2" />
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Navigation Tabs */}
        <div className="flex border-b border-teal-200 mb-8">
          <button
            className={`px-4 py-2 font-medium flex items-center ${
              activeTab === 'prescriptions' ? 'text-teal-600 border-b-2 border-teal-600' : 'text-gray-500'
            }`}
            onClick={() => setActiveTab('prescriptions')}
          >
            <ClipboardList className="h-4 w-4 mr-2" />
            Prescriptions
          </button>
          <button
            className={`px-4 py-2 font-medium flex items-center ${
              activeTab === 'appointments' ? 'text-teal-600 border-b-2 border-teal-600' : 'text-gray-500'
            }`}
            onClick={() => setActiveTab('appointments')}
          >
            <Calendar className="h-4 w-4 mr-2" />
            Appointments
          </button>
        </div>

        {activeTab === 'prescriptions' ? (
          <div className="space-y-8">
            {/* New Prescription Form */}
            <div className="bg-white border border-teal-200 rounded-lg shadow-sm">
              <div className="p-6 border-b border-teal-200">
                <h2 className="text-xl font-semibold text-gray-900">Create New Prescription</h2>
                <p className="text-sm text-gray-500 mt-1">Fill out the form to prescribe medication</p>
              </div>
              <div className="p-6">
                <form onSubmit={handleSubmitPrescription} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label htmlFor="patient" className="block text-sm font-medium text-gray-700">Patient</label>
                      <select
                        id="patient"
                        value={prescriptionForm.patientId}
                        onChange={(e) => setPrescriptionForm(prev => ({ ...prev, patientId: e.target.value }))}
                        className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                        required
                      >
                        <option value="">Select Patient</option>
                        {eligiblePatients.map(patient => (
                          <option key={patient.id} value={patient.id}>{patient.name}</option>
                        ))}
                      </select>
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="date" className="block text-sm font-medium text-gray-700">Date</label>
                      <input
                        type="date"
                        id="date"
                        value={prescriptionForm.date}
                        onChange={(e) => setPrescriptionForm(prev => ({ ...prev, date: e.target.value }))}
                        className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                        required
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="diagnosis" className="block text-sm font-medium text-gray-700">Diagnosis</label>
                    <input
                      id="diagnosis"
                      value={prescriptionForm.diagnosis}
                      onChange={(e) => setPrescriptionForm(prev => ({ ...prev, diagnosis: e.target.value }))}
                      placeholder="Enter diagnosis"
                      className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                      required
                    />
                  </div>

                  <div className="space-y-4">
                    <label className="block text-sm font-medium text-gray-700">Medicines</label>
                    {prescriptionForm.medicines.map((medicine, index) => (
                      <div key={index} className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="space-y-2">
                          <input
                            value={medicine.name}
                            onChange={(e) => handleMedicineChange(index, 'name', e.target.value)}
                            placeholder="Medicine Name"
                            className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                            required
                          />
                        </div>
                        <div className="space-y-2">
                          <input
                            value={medicine.dosage}
                            onChange={(e) => handleMedicineChange(index, 'dosage', e.target.value)}
                            placeholder="Dosage"
                            className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                            required
                          />
                        </div>
                        <div className="space-y-2">
                          <div className="flex items-center space-x-2">
                            <input
                              value={medicine.instructions}
                              onChange={(e) => handleMedicineChange(index, 'instructions', e.target.value)}
                              placeholder="Instructions"
                              className="w-full p-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-teal-500 focus:border-teal-500"
                              required
                            />
                            {index > 0 && (
                              <button
                                type="button"
                                onClick={() => handleRemoveMedicine(index)}
                                className="p-2 text-red-600 hover:text-red-700"
                              >
                                <X className="h-4 w-4" />
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                    <button
                      type="button"
                      onClick={handleAddMedicine}
                      className="flex items-center space-x-2 px-4 py-2 border border-teal-500 text-teal-600 rounded-md hover:bg-teal-50"
                    >
                      <Plus className="h-4 w-4" />
                      <span>Add Another Medicine</span>
                    </button>
                  </div>

                  <div className="flex justify-end space-x-4">
                    <button
                      type="button"
                      onClick={() => setShowPrescriptionForm(false)}
                      className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-4 py-2 bg-teal-600 text-white rounded-md hover:bg-teal-700"
                    >
                      Create Prescription
                    </button>
                  </div>
                </form>
              </div>
            </div>

            {/* Prescriptions List */}
            <div>
              <h2 className="text-xl font-semibold mb-4">Recent Prescriptions</h2>
              <div className="space-y-4">
                {prescriptions.map((prescription) => (
                  <div key={prescription.id} className="bg-white border border-teal-100 rounded-lg shadow-sm">
                    <div className="p-6 border-b border-teal-100">
                      <div className="flex justify-between">
                        <h3 className="text-lg font-semibold text-gray-900">Prescription for {prescription.patient_name}</h3>
                        <span className="text-sm text-gray-500">{prescription.date}</span>
                      </div>
                      <p className="text-sm text-gray-500 mt-1">Diagnosis: {prescription.diagnosis}</p>
                    </div>
                    <div className="p-6">
                      <div className="space-y-4">
                        {prescription.medicines.map((medicine, index) => (
                          <div key={index} className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                              <p className="text-sm font-medium text-gray-500">Medicine</p>
                              <p className="text-gray-900">{medicine.name}</p>
                            </div>
                            <div>
                              <p className="text-sm font-medium text-gray-500">Dosage</p>
                              <p className="text-gray-900">{medicine.dosage}</p>
                            </div>
                            <div>
                              <p className="text-sm font-medium text-gray-500">Instructions</p>
                              <p className="text-gray-900">{medicine.instructions}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-8">
            {/* Upcoming Appointment */}
            <div>
              <h2 className="text-xl font-semibold mb-4">Next Appointment</h2>
              {appointments.filter(a => a.status === 'scheduled').length > 0 ? (
                <div className="bg-white border border-teal-100 rounded-lg shadow-sm">
                  <div className="p-6 border-b border-teal-100">
                    <div className="flex justify-between items-center">
                      <div>
                        <h3 className="text-lg font-semibold text-gray-900">
                          {appointments.filter(a => a.status === 'scheduled')[0].patient_name}
                        </h3>
                        <p className="text-sm text-gray-500 mt-1">
                          {appointments.filter(a => a.status === 'scheduled')[0].purpose}
                        </p>
                      </div>
                      <button
                        onClick={() => handleRequestAccess(appointments.filter(a => a.status === 'scheduled')[0].patient_id)}
                        className="flex items-center space-x-2 px-4 py-2 bg-teal-600 text-white rounded-md hover:bg-teal-700"
                      >
                        <Shield className="h-4 w-4" />
                        <span>Request Data Access</span>
                      </button>
                    </div>
                    <div className="mt-4 flex justify-between items-center">
                      <span className="text-sm text-gray-500">
                        {appointments.filter(a => a.status === 'scheduled')[0].date} at {appointments.filter(a => a.status === 'scheduled')[0].time}
                      </span>
                      <div className="flex space-x-2">
                        <button 
                          onClick={() => handleCompleteAppointment(appointments.filter(a => a.status === 'scheduled')[0].id)}
                          className="flex items-center space-x-2 px-4 py-2 border border-teal-500 text-teal-600 rounded-md hover:bg-teal-50"
                        >
                          <Check className="h-4 w-4" />
                          <span>Complete</span>
                        </button>
                        <button 
                          onClick={() => handleCancelAppointment(appointments.filter(a => a.status === 'scheduled')[0].id)}
                          className="flex items-center space-x-2 px-4 py-2 border border-red-300 text-red-600 rounded-md hover:bg-red-50"
                        >
                          <X className="h-4 w-4" />
                          <span>Cancel</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6 text-center">
                  <p className="text-gray-500">No upcoming appointments</p>
                </div>
              )}
            </div>

            {/* Completed Appointments */}
            <div>
              <h2 className="text-xl font-semibold mb-4">Completed Appointments</h2>
              <div className="space-y-4">
                {appointments.filter(a => a.status === 'completed').map((appointment) => (
                  <div key={appointment.id} className="bg-gray-50 border border-gray-200 rounded-lg shadow-sm">
                    <div className="p-6 border-b border-gray-200">
                      <div className="flex justify-between items-center">
                        <div>
                          <h3 className="text-lg font-semibold text-gray-900">{appointment.patient_name}</h3>
                          <p className="text-sm text-gray-500 mt-1">{appointment.purpose}</p>
                        </div>
                        <button
                          onClick={() => handleRequestAccess(appointment.patient_id)}
                          className="flex items-center space-x-2 px-4 py-2 bg-teal-600 text-white rounded-md hover:bg-teal-700"
                        >
                          <Shield className="h-4 w-4" />
                          <span>Request Data Access</span>
                        </button>
                      </div>
                      <div className="mt-4 flex justify-between items-center">
                        <span className="text-sm text-gray-500">
                          {appointment.date} at {appointment.time}
                        </span>
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          Completed
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
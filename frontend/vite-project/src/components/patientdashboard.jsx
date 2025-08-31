import { useState, useEffect, useRef } from 'react'
import { Users, User, Shield, Calendar, Clock, Plus, Upload, Bell, Check, X, ClipboardList, Download, FileText, HeartPulse, Pill, LogOut, ChevronDown } from "lucide-react"
import { API_BASE_URL, fetchWithAuth } from '../utils/api'


function PatientDashboard() {
  const [currentUser, setCurrentUser] = useState(null)
  const [medicalRecords, setMedicalRecords] = useState([])
  const [prescriptions, setPrescriptions] = useState([])
  const [appointments, setAppointments] = useState([])
  const [accessRequests, setAccessRequests] = useState([])
  const [reminders, setReminders] = useState([])
  const [doctorAccess, setDoctorAccess] = useState([])
  const [activeTab, setActiveTab] = useState('prescriptions')
  const [doctorView, setDoctorView] = useState('patients')
  const [showReminderModal, setShowReminderModal] = useState(false)
  const [currentReminder, setCurrentReminder] = useState(null)
  const [reminderTime, setReminderTime] = useState('08:00')
  const [selectedDays, setSelectedDays] = useState([])
  const [newPrescription, setNewPrescription] = useState({
    medication: '',
    dosage: '',
    instructions: ''
  })
  const [newAppointment, setNewAppointment] = useState({
    doctorId: '',
    doctorName: '',
    slot: '',
    purpose: ''
  })
  const [showNewAppointmentModal, setShowNewAppointmentModal] = useState(false)
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)

  const [showUserDropdown, setShowUserDropdown] = useState(false)
  const [userMedicalHistory, setUserMedicalHistory] = useState({
    disease: '',
    allergies: '',
    surgery_history: ''
  })

  const [newReminder, setNewReminder] = useState({
    medicineName: '',
    dosage: '',
    time: '08:00',
    days: []
  })

  const [showEditMedicalHistoryModal, setShowEditMedicalHistoryModal] = useState(false)
  const [editableMedicalHistory, setEditableMedicalHistory] = useState({
    disease: '',
    allergies: '',
    surgery_history: ''
  })

  const [availableDoctors, setAvailableDoctors] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const daysOfWeek = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true)
        setError(null)
        
        // Fetch user data
        const userData = JSON.parse(localStorage.getItem('user'))
        if (!userData) {
          throw new Error('No user data found')
        }
        setCurrentUser(userData)

        // Fetch dashboard data
        const dashboardData = await fetchWithAuth('/patient/dashboard')
        
        // Update state with fetched data
        setUserMedicalHistory(dashboardData.medical_history || {
          disease: '',
          allergies: '',
          surgery_history: ''
        })
        setPrescriptions(dashboardData.prescriptions || [])
        setAppointments(dashboardData.appointments || [])
        setMedicalRecords(dashboardData.lab_reports || [])
        setAccessRequests(dashboardData.access_requests || [])
        setDoctorAccess(dashboardData.current_access || [])
        setReminders(dashboardData.reminders || [])
        setAvailableDoctors(dashboardData.available_doctors || [])

        // --- ✅ NEW: Fetch doctor list separately ---
      const doctorsList = await fetchWithAuth('/patient/available-doctors')
      // normalize availability_slots to array on each doctor
      const normalized = (doctorsList || []).map(d => {
        let slots = d.availability_slots || []
        if (typeof slots === 'string') {
          try { slots = JSON.parse(slots) } catch (err) { slots = slots.split(',').map(s=>s.trim()).filter(Boolean) }
        }
        return { ...d, availability_slots: Array.isArray(slots) ? slots : [slots] }
      })
      setAvailableDoctors(normalized)
      
      } catch (err) {
        console.error('Error fetching dashboard data:', err)
        setError(err.message || 'Failed to fetch dashboard data')
      } finally {
        setLoading(false)
      }
    }

    fetchDashboardData()
  }, [])

  const handleAuthSubmit = (e) => {
    e.preventDefault()
    if (username && password && (isLoginView || role)) {
      setCurrentUser({ username, role })
      setIsAuthenticated(true)
    }
  }

  const handleAddPrescription = (e) => {
    e.preventDefault()
    const prescription = {
      ...newPrescription,
      id: Date.now().toString(),
      date: new Date().toISOString().split('T')[0],
      doctor: 'Dr. Smith'
    }
    setPrescriptions([...prescriptions, prescription])
    setNewPrescription({ medication: '', dosage: '', instructions: '' })
  }

  const handleAddAppointment = async () => {
  try {
    const response = await fetchWithAuth('/patient/appointments', {
      method: 'POST',
      body: JSON.stringify({
        doctor_id: parseInt(newAppointment.doctorId),
        date_time: newAppointment.slot,
        purpose: newAppointment.purpose
      })
    });

    // response contains 'appointment' object
    const appt = response.appointment || { id: Date.now(), doctor_name: newAppointment.doctorName, date: new Date(newAppointment.slot).toISOString().split('T')[0], time: new Date(newAppointment.slot).toISOString().split('T')[1].slice(0,5), purpose: newAppointment.purpose, status: 'Pending' };
    setAppointments([...appointments, appt]);
    setNewAppointment({ doctorId: '', doctorName: '', slot: '', purpose: '' });
    setShowNewAppointmentModal(false);
  } catch (error) {
    console.error('Error scheduling appointment:', error);
    alert(error.message || 'Failed to schedule appointment. Please try again.');
  }
};


  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0])
    }
  }

  const handleUploadRecord = () => {
    if (selectedFile) {
      const reader = new FileReader()
      reader.onload = (event) => {
        const newRecord = {
          id: Date.now().toString(),
          title: selectedFile.name,
          type: 'lab_report',
          date: new Date().toISOString().split('T')[0],
          details: 'Uploaded medical record',
          fileUrl: event.target.result,
          fileName: selectedFile.name
        }
        setMedicalRecords([...medicalRecords, newRecord])
        setShowUploadModal(false)
        setSelectedFile(null)
      }
      reader.readAsDataURL(selectedFile)
    }
  }

  const handleDownloadFile = (fileUrl, fileName) => {
    const link = document.createElement('a')
    link.href = fileUrl
    link.download = fileName
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const handleAccessRequest = (requestId, action) => {
    setAccessRequests(accessRequests.map(request => 
      request.id === requestId 
        ? { ...request, status: action }
        : request
    ))
  }

  const handleApproveAccess = async (requestId) => {
    try {
      await fetchWithAuth(`/patient/access-requests/${requestId}/approve`, {
        method: 'PUT'
      })
      
      // Refresh access requests and current access
      const [requests, access] = await Promise.all([
        fetchWithAuth('/patient/access-requests'),
        fetchWithAuth('/patient/current-access')
      ])
      
      setAccessRequests(requests)
      setDoctorAccess(access)
    } catch (err) {
      console.error('Error approving access:', err)
      alert(err.message || 'Failed to approve access request')
    }
  }

  const handleRejectAccess = async (requestId) => {
    try {
      await fetchWithAuth(`/patient/access-requests/${requestId}/reject`, {
        method: 'PUT'
      })
      
      // Refresh access requests
      const requests = await fetchWithAuth('/patient/access-requests')
      setAccessRequests(requests)
    } catch (err) {
      console.error('Error rejecting access:', err)
      alert(err.message || 'Failed to reject access request')
    }
  }

  const handleRevokeAccess = async (accessId) => {
    try {
      await fetchWithAuth(`/patient/current-access/${accessId}`, {
        method: 'DELETE'
      })
      
      // Refresh current access
      const access = await fetchWithAuth('/patient/current-access')
      setDoctorAccess(access)
    } catch (err) {
      console.error('Error revoking access:', err)
      alert(err.message || 'Failed to revoke access')
    }
  }

  const handleCompleteAppointment = (appointmentId) => {
    setAppointments(appointments.map(appt => 
      appt.id === appointmentId 
        ? { ...appt, status: 'completed' }
        : appt
    ))
  }

  const handleCancelAppointment = (appointmentId) => {
    setAppointments(appointments.map(appt => 
      appt.id === appointmentId 
        ? { ...appt, status: 'cancelled' }
        : appt
    ))
  }

  const handleSetReminder = (prescription) => {
    const existingReminder = reminders.find(r => r.prescriptionId === prescription.id)
    if (existingReminder) {
      setCurrentReminder(existingReminder)
      setReminderTime(existingReminder.time)
      setSelectedDays(existingReminder.days)
    } else {
      setCurrentReminder(null)
      setReminderTime('08:00')
      setSelectedDays([])
    }
    setShowReminderModal(true)
  }

  const handleDeleteReminder = async (reminderId) => {
    if (!window.confirm('Are you sure you want to delete this reminder?')) return;
    try {
      await fetchWithAuth(`/patient/reminders/${reminderId}`, { method: 'DELETE' });

      const data = await fetchWithAuth('/patient/dashboard');
      setReminders(data.reminders);
    } catch (error) {
      console.error('Error deleting reminder:', error);
      alert(error.message || 'Failed to delete reminder');
    }
  };

  const handleDeleteAppointment = async (appointmentId) => {
    if (!window.confirm('Are you sure you want to delete this appointment?')) return;
    try {
      await fetchWithAuth(`/patient/appointments/${appointmentId}`, { method: 'DELETE' });
      // remove from local state
      setAppointments(prev => prev.filter(a => a.appointment_id !== appointmentId && a.id !== appointmentId && a.appointmentId !== appointmentId));
      // refresh dashboard data lightly
      const data = await fetchWithAuth('/patient/dashboard');
      setAppointments(data.appointments || []);
    } catch (error) {
      console.error('Error deleting appointment:', error);
      alert(error.message || 'Failed to delete appointment');
    }
  };


  const toggleDaySelection = (day) => {
    setSelectedDays(prev => 
      prev.includes(day) 
        ? prev.filter(d => d !== day)
        : [...prev, day]
    )
  }

  const handleLogout = () => {
    // Clear user session and redirect to welcome page
    localStorage.removeItem('token')
    window.location.href = '/login'
  }

  const handleSaveReminder = () => {
    if (!currentReminder) return

    const updatedReminder = {
      ...currentReminder,
      time: reminderTime,
      days: selectedDays
    }

    setReminders(prev => {
      const existingIndex = prev.findIndex(r => r.id === updatedReminder.id)
      if (existingIndex >= 0) {
        const newReminders = [...prev]
        newReminders[existingIndex] = updatedReminder
        return newReminders
      } else {
        return [...prev, updatedReminder]
      }
    })

    setShowReminderModal(false)
  }

  const handleEditMedicalHistory = () => {
    setEditableMedicalHistory({
      disease: userMedicalHistory.disease || '',
      allergies: userMedicalHistory.allergies || '',
      surgery_history: userMedicalHistory.surgery_history || ''
    })
    setShowEditMedicalHistoryModal(true)
  }

  const handleSaveMedicalHistory = async () => {
  try {
    await fetchWithAuth('/patient/medical-history', {
      method: 'PUT',
      body: JSON.stringify(editableMedicalHistory)
    });

    setUserMedicalHistory(editableMedicalHistory);
    setShowEditMedicalHistoryModal(false);
    alert('Medical history updated successfully!');
  } catch (error) {
    console.error('Error updating medical history:', error);
    alert(error.message || 'Failed to update medical history. Please try again.');
  }
};


  const handleAddReminder = async (prescriptionId, medicineName, time, startDate, endDate) => {
  try {
    await fetchWithAuth('/patient/reminders', {
      method: 'POST',
      body: JSON.stringify({
        prescription_id: prescriptionId,
        medicine_name: medicineName,
        time,
        start_date: startDate,
        end_date: endDate
      })
    });

    const data = await fetchWithAuth('/patient/dashboard');
    setReminders(data.reminders);
  } catch (error) {
    console.error('Error adding reminder:', error);
  }
};


  if (loading) {
    return <div>Loading...</div>
  }

  if (error) {
    return <div>Error: {error}</div>
  }

  return (
  <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <h1 className="text-3xl font-bold text-gray-900">Patient Dashboard</h1>
            <div className="flex items-center space-x-4">
              <span className="text-gray-700">Welcome, {currentUser?.name}</span>
              <button
                onClick={handleLogout}
                className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {/* Available Doctors Section */}
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Available Doctors</h2>
          {availableDoctors.length === 0 ? (
            <p className="text-gray-500">No doctors available</p>
          ) : (
            <ul className="divide-y divide-gray-200">
              {availableDoctors.map((doc) => (
                <li key={doc.id} className="py-2 flex flex-col">
                  <span className="font-medium">{doc.name}</span>
                  <span className="text-sm text-gray-500">{doc.specialization || 'General'}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        {/* Debug Information */}
        <div className="bg-white shadow rounded-lg p-4 mb-6">
          <h2 className="text-lg font-medium text-gray-900 mb-2">Debug Information</h2>
          <pre className="bg-gray-100 p-2 rounded overflow-auto">
            {JSON.stringify({
              currentUser,
              medicalHistory: userMedicalHistory,
              prescriptionsCount: prescriptions.length,
              appointmentsCount: appointments.length,
              accessRequestsCount: accessRequests.length,
              doctorAccessCount: doctorAccess.length,
              remindersCount: reminders.length
            }, null, 2)}
          </pre>
        </div>

        {/* Medical History Section */}
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold text-gray-900">Medical History</h2>
            <button
              onClick={() => setShowEditMedicalHistoryModal(true)}
              className="bg-teal-600 text-white px-4 py-2 rounded-md hover:bg-teal-700"
            >
              Edit History
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <h3 className="text-sm font-medium text-gray-500">Disease</h3>
              <p className="mt-1 text-gray-900">{userMedicalHistory.disease || 'No disease recorded'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500">Allergies</h3>
              <p className="mt-1 text-gray-900">{userMedicalHistory.allergies || 'No allergies recorded'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500">Surgery History</h3>
              <p className="mt-1 text-gray-900">{userMedicalHistory.surgery_history || 'No surgery history recorded'}</p>
            </div>
          </div>
        </div>

        {/* Prescriptions Section */}
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Prescriptions</h2>
          {prescriptions.length === 0 ? (
            <p className="text-gray-500">No prescriptions found</p>
          ) : (
            <div className="space-y-4">
              {prescriptions.map((prescription) => (
                <div key={prescription.id} className="border rounded-lg p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900">
                        Dr. {prescription.doctor_name}
                      </h3>
                      <p className="text-sm text-gray-500">
                        Date: {prescription.date_issued}
                      </p>
                      <p className="text-sm text-gray-700 mt-2">
                        Diagnosis: {prescription.diagnosis}
                      </p>
                    </div>
                    <button
                      onClick={() => handleSetReminder(prescription)}
                      className="bg-teal-600 text-white px-3 py-1 rounded-md hover:bg-teal-700"
                    >
                      Set Reminder
                    </button>
                  </div>
                  <div className="mt-4">
                    <h4 className="text-sm font-medium text-gray-700">Medicines:</h4>
                    <ul className="mt-2 space-y-2">
                      {prescription.medicines.map((medicine, index) => (
                        <li key={index} className="text-sm text-gray-600">
                          {medicine.name} - {medicine.dosage} ({medicine.frequency})
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Appointments Section */}
        <div className="bg-white shadow rounded-lg p-6 mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold text-gray-900">Appointments</h2>
            <button
              onClick={() => setShowNewAppointmentModal(true)}
              className="bg-teal-600 text-white px-4 py-2 rounded-md hover:bg-teal-700"
            >
              Schedule Appointment
            </button>
          </div>
          {appointments.length === 0 ? (
            <p className="text-gray-500">No appointments scheduled</p>
          ) : (
            <div className="space-y-4">
              {appointments.map((appointment) => (
                <div key={appointment.id || appointment.appointment_id} className="border rounded-lg p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900">
                        Dr. {appointment.doctor_name}
                      </h3>
                      <p className="text-sm text-gray-500">
                        Date: {appointment.date} at {appointment.time}
                      </p>
                      <p className="text-sm text-gray-700 mt-2">
                        Purpose: {appointment.purpose}
                      </p>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-sm ${
                      appointment.status === 'completed' ? 'bg-green-100 text-green-800' :
                      appointment.status === 'cancelled' ? 'bg-red-100 text-red-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {appointment.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Access Control Section */}
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Access Control</h2>
          
          {/* Pending Access Requests */}
          <div className="mb-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Pending Access Requests</h3>
            {accessRequests.length === 0 ? (
              <p className="text-gray-500">No pending access requests</p>
            ) : (
              <div className="space-y-4">
                {accessRequests.map((request) => (
                  <div key={request.id} className="border rounded-lg p-4">
                    <div className="flex justify-between items-start">
                      <div>
                        <h4 className="text-lg font-medium text-gray-900">
                          Dr. {request.doctor_name}
                        </h4>
                        <p className="text-sm text-gray-500">
                          Requested on: {request.request_date}
                        </p>
                        <p className="text-sm text-gray-700 mt-2">
                          Purpose: {request.purpose}
                        </p>
                      </div>
                      <div className="space-x-2">
                        <button
                          onClick={() => handleApproveAccess(request.id)}
                          className="bg-green-600 text-white px-3 py-1 rounded-md hover:bg-green-700"
                        >
                          Approve
                        </button>
                        <button
                          onClick={() => handleRejectAccess(request.id)}
                          className="bg-red-600 text-white px-3 py-1 rounded-md hover:bg-red-700"
                        >
                          Reject
                        </button>
                      </div>
                      {(!appointment.status || (appointment.status !== 'completed' && appointment.status !== 'cancelled')) && (
                        <div className="mt-3 flex space-x-2">
                          <button
                            onClick={() => handleDeleteAppointment(appointment.appointment_id || appointment.id || appointment.id)}
                            className="px-3 py-1 rounded-md bg-red-600 text-white hover:bg-red-700"
                          >
                            Delete
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Current Access */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Current Access</h3>
            {doctorAccess.length === 0 ? (
              <p className="text-gray-500">No doctors currently have access</p>
            ) : (
              <div className="space-y-4">
                {doctorAccess.map((access) => (
                  <div key={access.doctor_id} className="border rounded-lg p-4">
                    <div className="flex justify-between items-start">
                      <div>
                        <h4 className="text-lg font-medium text-gray-900">
                          Dr. {access.doctor_name}
                        </h4>
                        <p className="text-sm text-gray-500">
                          Access granted on: {access.access_date}
                        </p>
                        <p className="text-sm text-gray-700 mt-2">
                          Purpose: {access.purpose}
                        </p>
                      </div>
                      <button
                        onClick={() => handleRevokeAccess(access.doctor_id)}
                        className="bg-red-600 text-white px-3 py-1 rounded-md hover:bg-red-700"
                      >
                        Revoke Access
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Modals */}
      {showReminderModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-medium text-gray-900 mb-4">
              Add Medicine Reminder
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Medicine Name</label>
                <input
                  type="text"
                  value={newReminder.medicineName}
                  onChange={(e) => setNewReminder({...newReminder, medicineName: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                  placeholder="Enter medicine name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Dosage</label>
                <input
                  type="text"
                  value={newReminder.dosage}
                  onChange={(e) => setNewReminder({...newReminder, dosage: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                  placeholder="Enter dosage (e.g., 500mg)"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Time</label>
                <input
                  type="time"
                  value={newReminder.time}
                  onChange={(e) => setNewReminder({...newReminder, time: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Days</label>
                <div className="grid grid-cols-4 gap-2">
                  {daysOfWeek.map(day => (
                    <button
                      key={day}
                      onClick={() => {
                        const newDays = newReminder.days.includes(day)
                          ? newReminder.days.filter(d => d !== day)
                          : [...newReminder.days, day]
                        setNewReminder({...newReminder, days: newDays})
                      }}
                      className={`px-3 py-2 rounded-md text-sm font-medium ${
                        newReminder.days.includes(day)
                          ? 'bg-teal-600 text-white'
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                      }`}
                    >
                      {day}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => setShowReminderModal(false)}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (newReminder.medicineName && newReminder.dosage && newReminder.days.length > 0) {
                    const reminder = {
                      id: Date.now().toString(),
                      ...newReminder
                    }
                    setReminders([...reminders, reminder])
                    setShowReminderModal(false)
                  }
                }}
                disabled={!newReminder.medicineName || !newReminder.dosage || newReminder.days.length === 0}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-teal-600 hover:bg-teal-700 disabled:opacity-50"
              >
                Save Reminder
              </button>
            </div>
          </div>
        </div>
      )}

      {showNewAppointmentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Schedule New Appointment</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Doctor</label>
                <select
                  value={newAppointment.doctorId}
                  onChange={(e) => {
                    const doctor = availableDoctors.find(d => d.id === parseInt(e.target.value));
                    setNewAppointment({
                      ...newAppointment,
                      doctorId: e.target.value,
                      doctorName: doctor ? doctor.name : ''
                    });
                    // If selected doctor has availability, set first slot as selected
                    if (doctor && doctor.availability_slots && doctor.availability_slots.length > 0) {
                      setNewAppointment(prev => ({ ...prev, slot: doctor.availability_slots[0] }))
                    }
                  }}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                  required
                >
                  <option value="">Select a doctor</option>
                  {availableDoctors.map(doctor => (
                    <option key={doctor.id} value={doctor.id}>
                      {doctor.name} - {doctor.specialization}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Available Slots</label>
                <select
                  value={newAppointment.slot}
                  onChange={(e) => setNewAppointment({...newAppointment, slot: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                  required
                >
                  <option value="">Select a slot</option>
                  {(availableDoctors.find(d => d.id === parseInt(newAppointment.doctorId))?.availability_slots || []).map((s, idx) => (
                    <option key={idx} value={s}>{new Date(s).toLocaleString()}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Purpose</label>
                <input
                  type="text"
                  value={newAppointment.purpose}
                  onChange={(e) => setNewAppointment({...newAppointment, purpose: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                  placeholder="Enter appointment purpose"
                />
              </div>
            </div>
            <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => {
                  setShowNewAppointmentModal(false)
                  setNewAppointment({
                    doctorId: '',
                    doctorName: '',
                    date: '',
                    time: '',
                    purpose: ''
                  })
                }}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (newAppointment.doctorId && newAppointment.date && newAppointment.time && newAppointment.purpose) {
                    handleAddAppointment()
                    setShowNewAppointmentModal(false)
                  }
                }}
                disabled={!newAppointment.doctorId || !newAppointment.date || !newAppointment.time || !newAppointment.purpose}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-teal-600 hover:bg-teal-700 disabled:opacity-50"
              >
                Schedule
              </button>
            </div>
          </div>
        </div>
      )}

      {showEditMedicalHistoryModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Edit Medical History</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Disease</label>
                <input
                  type="text"
                  value={editableMedicalHistory.disease}
                  onChange={(e) => setEditableMedicalHistory({...editableMedicalHistory, disease: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Allergies</label>
                <input
                  type="text"
                  value={editableMedicalHistory.allergies}
                  onChange={(e) => setEditableMedicalHistory({...editableMedicalHistory, allergies: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Surgery History</label>
                <input
                  type="text"
                  value={editableMedicalHistory.surgery_history}
                  onChange={(e) => setEditableMedicalHistory({...editableMedicalHistory, surgery_history: e.target.value})}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-teal-500 focus:ring-teal-500"
                />
              </div>
            </div>
            <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => setShowEditMedicalHistoryModal(false)}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveMedicalHistory}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-teal-600 hover:bg-teal-700"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {showUploadModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Upload Medical Record</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Select File</label>
                <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                  <div className="space-y-1 text-center">
                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                    <div className="flex text-sm text-gray-600">
                      <label
                        htmlFor="file-upload"
                        className="relative cursor-pointer bg-white rounded-md font-medium text-teal-600 hover:text-teal-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-teal-500"
                      >
                        <span>Upload a file</span>
                        <input
                          id="file-upload"
                          name="file-upload"
                          type="file"
                          className="sr-only"
                          onChange={handleFileSelect}
                        />
                      </label>
                      <p className="pl-1">or drag and drop</p>
                    </div>
                    <p className="text-xs text-gray-500">
                      PDF, DOC, DOCX, JPG, PNG up to 10MB
                    </p>
                  </div>
                </div>
                {selectedFile && (
                  <div className="mt-2 text-sm text-gray-600">
                    Selected file: {selectedFile.name}
                  </div>
                )}
              </div>
            </div>
            <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => {
                  setShowUploadModal(false)
                  setSelectedFile(null)
                }}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleUploadRecord}
                disabled={!selectedFile}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-teal-600 hover:bg-teal-700 disabled:opacity-50"
              >
                Upload
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default PatientDashboard

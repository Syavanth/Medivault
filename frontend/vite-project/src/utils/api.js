// API base URL from environment variable
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';

// Helper function to handle API responses
const handleResponse = async (response) => {
  const data = await response.json();
  if (!response.ok) {
    console.error('API Error:', {
      status: response.status,
      statusText: response.statusText,
      data,
    });
    throw new Error(data.error || 'API request failed');
  }
  return data;
};

// Login function
export const login = async (credentials) => {
  console.log('Attempting login for:', credentials.email);
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  });
  const data = await handleResponse(response);

  // Save token and user info locally
  if (data.access_token) {
    localStorage.setItem('token', data.access_token);
    localStorage.setItem('user', JSON.stringify(data.user));
  }

  console.log('Login successful');
  return data;
};

// Register function
export const register = async (userData) => {
  console.log('Attempting registration for:', userData.email);
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(userData),
  });
  return handleResponse(response);
};

// Logout function
export const logout = async () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  console.log('Logged out locally');
};

// Authenticated fetch function for patient/doctor routes


// utils/api.js or similar
export async function fetchWithAuth(url, options = {}) {
  const token = localStorage.getItem('token');
  if (!token) throw new Error('No auth token found');

  const headers = {
    ...options.headers,
    'Authorization': `Bearer ${token}`,
  };

  // Default Content-Type only when body is JSON
  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }

  // If body is an object, stringify it
  let body = options.body;
  if (body && typeof body === 'object' && !(body instanceof FormData)) {
    body = JSON.stringify(body);
  }

  // If a relative path is provided (starts with '/'), prefix the API base URL
  const fetchUrl = url.startsWith('http') ? url : `${API_BASE_URL}${url}`;

  const response = await fetch(fetchUrl, {
    ...options,
    headers,
    body
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.msg || error.error || 'Request failed');
  }
  return await response.json();
}


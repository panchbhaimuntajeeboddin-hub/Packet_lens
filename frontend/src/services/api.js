/**
 * PacketLens API Service
 * Encapsulates all backend REST communications.
 * Transmits secure HttpOnly session cookies across Direct (127.0.0.1:8000) and Vite /api proxy.
 */

const CONFIGURED_URL = import.meta.env.VITE_API_BASE_URL;
let activeBaseUrl = CONFIGURED_URL !== undefined ? CONFIGURED_URL : '';

function getUrl(path) {
  return `${activeBaseUrl}${path}`;
}

/**
 * Common fetch helper ensuring credentials: 'include' for HttpOnly cookies.
 */
async function secureFetch(path, options = {}) {
  const fetchOptions = {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  };

  const response = await fetch(getUrl(path), fetchOptions);
  return response;
}

/**
 * Checks backend health and connectivity.
 */
export async function checkHealth() {
  try {
    const response = await fetch(getUrl('/api/health'), { credentials: 'include' });
    if (response.ok) {
      return await response.json();
    }
  } catch (err) {
    if (activeBaseUrl !== '') {
      try {
        const fallbackRes = await fetch('/api/health', { credentials: 'include' });
        if (fallbackRes.ok) {
          activeBaseUrl = '';
          return await fallbackRes.json();
        }
      } catch (e) {
        // Fall through
      }
    }
    throw new Error('Backend is unreachable. Please verify FastAPI is running on port 8000.');
  }

  throw new Error('Backend returned unexpected status.');
}

/* ==========================================================================
   AUTHENTICATION API METHODS
   ========================================================================== */

/**
 * Authenticates analyst credentials and establishes HttpOnly session cookie.
 */
export async function loginUser({ email, password }) {
  const response = await secureFetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Login failed. Please verify your credentials.');
  }
  return data;
}

/**
 * Registers a new analyst account and automatically logs in via HttpOnly cookie.
 */
export async function registerUser({ full_name, email, password, confirm_password }) {
  const response = await secureFetch('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      full_name,
      email,
      password,
      confirm_password,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Registration failed. Please check your inputs.');
  }
  return data;
}

/**
 * Terminates active analyst session and clears HttpOnly cookie.
 */
export async function logoutUser() {
  const response = await secureFetch('/api/auth/logout', {
    method: 'POST',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Failed to logout properly.');
  }
  return data;
}

/**
 * Inspects current analyst identity from HttpOnly session cookie.
 */
export async function getCurrentUser() {
  const response = await secureFetch('/api/auth/me', {
    method: 'GET',
  });

  if (response.status === 401) {
    return null;
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Failed to verify session.');
  }
  return data;
}

/* ==========================================================================
   CAPTURE ANALYSIS & DASHBOARD API METHODS
   ========================================================================== */

/**
 * Retrieves aggregate metrics strictly for the authenticated analyst's captures.
 */
export async function getDashboardStats() {
  const response = await secureFetch('/api/dashboard/stats', {
    method: 'GET',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Failed to load dashboard statistics.');
  }
  return data;
}

/**
 * Uploads a .pcap or .pcapng capture file with real-time progress callbacks.
 */
export function uploadCapture(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append('file', file);

    xhr.open('POST', getUrl('/api/analyze'));
    xhr.withCredentials = true; // Essential for sending the HttpOnly session cookie

    if (xhr.upload && onProgress) {
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          const percentComplete = Math.round((event.loaded / event.total) * 100);
          onProgress(percentComplete);
        }
      };
    }

    xhr.onload = () => {
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(data);
        } else {
          reject(new Error(data.detail || `Upload failed with status ${xhr.status}`));
        }
      } catch (err) {
        reject(new Error('Invalid response from server'));
      }
    };

    xhr.onerror = () => {
      reject(new Error('Network error during file upload. Ensure backend is running.'));
    };

    xhr.send(formData);
  });
}

/**
 * Retrieves full analysis session metadata and statistics.
 */
export async function getAnalysisSession(analysisId) {
  const response = await secureFetch(`/api/analysis/${analysisId}`, {
    method: 'GET',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Failed to fetch session (${response.status})`);
  }
  return data;
}

/**
 * Retrieves computed traffic statistics for an analysis session.
 */
export async function getAnalysisStatistics(analysisId) {
  const response = await secureFetch(`/api/analysis/${analysisId}/statistics`, {
    method: 'GET',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Failed to fetch statistics (${response.status})`);
  }
  return data;
}

/**
 * Retrieves paginated, filterable dissected packet records.
 */
export async function getAnalysisPackets(analysisId, {
  page = 1,
  pageSize = 50,
  protocol = '',
  ip = '',
  port = '',
  search = '',
} = {}) {
  const params = new URLSearchParams();
  params.append('page', page);
  params.append('page_size', pageSize);
  if (protocol) params.append('protocol', protocol);
  if (ip) params.append('ip', ip);
  if (port) params.append('port', port);
  if (search) params.append('search', search);

  const response = await secureFetch(`/api/analysis/${analysisId}/packets?${params.toString()}`, {
    method: 'GET',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || `Failed to fetch packets (${response.status})`);
  }
  return data;
}

/**
 * Generates direct download URL for exporting analysis as CSV.
 */
export function getExportCsvUrl(analysisId) {
  return getUrl(`/api/analysis/${analysisId}/export`);
}

/**
 * Lists recently analyzed capture sessions for the authenticated user.
 */
export async function listRecentAnalyses() {
  const response = await secureFetch('/api/analyses', {
    method: 'GET',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Failed to load analysis history');
  }
  return data;
}

/**
 * Deletes a capture analysis session and its dissected packets.
 */
export async function deleteAnalysis(analysisId) {
  const response = await secureFetch(`/api/analysis/${analysisId}`, {
    method: 'DELETE',
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || 'Failed to delete capture session.');
  }
  return data;
}

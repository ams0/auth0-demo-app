import React, { useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';

const ApiCallButton = () => {
  const { getAccessTokenSilently } = useAuth0();
  const [apiResponse, setApiResponse] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleApiCall = async () => {
    setIsLoading(true);
    setError(null);
    setApiResponse('');

    try {
      const token = await getAccessTokenSilently({
        audience: 'http://localhost:3000/api/v1/admin', // Make sure this matches your API identifier in Auth0
        scope: 'openid profile email offline_access', // Ensure necessary scopes are requested
      });

      const response = await fetch('http://localhost:3000/api/v1/admin', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json', // Optional: Add if your API expects a JSON body
        },
        // body: JSON.stringify({ key: 'value' }) // Optional: Add body if needed
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json(); // Or response.text() if it's not JSON
      setApiResponse(JSON.stringify(data, null, 2));

    } catch (e) {
      console.error('API call failed:', e);
      setError(`API call failed: ${e.message}`);
      setApiResponse(''); // Clear any previous response on error
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="api-call-section">
      <button 
        className="auth-button api-call-button" 
        onClick={handleApiCall} 
        disabled={isLoading}
      >
        {isLoading ? 'Calling API...' : 'Make the call'}
      </button>
      
      {error && <div className="error api-error">Error: {error}</div>}

      {apiResponse && (
        <div className="api-response">
          <h4>API Response:</h4>
          <pre>{apiResponse}</pre>
        </div>
      )}
    </div>
  );
};

export default ApiCallButton;

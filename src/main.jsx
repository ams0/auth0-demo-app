import React from 'react'
import ReactDOM from 'react-dom/client'
import { Auth0Provider } from '@auth0/auth0-react'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Auth0Provider
      domain={import.meta.env.VITE_AUTH0_DOMAIN} // Use environment variable for domain
      clientId={import.meta.env.VITE_AUTH0_CLIENT_ID} // Use environment variable for client ID
      authorizationParams={{
        redirect_uri: window.location.origin,
        // Provide audiences as a space-separated string
        audience: "http://localhost:3000/api/v1/admin", 
        scope: "openid profile email offline_access" // Include offline_access to get refresh tokens
      }}
      useRefreshTokens={true} // This enables refresh token rotation
      cacheLocation="localstorage" // Options: 'memory' or 'localstorage'
    >
      <App />
    </Auth0Provider>
  </React.StrictMode>,
)
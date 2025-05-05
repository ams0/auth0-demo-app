import { useState } from 'react'
import { useAuth0 } from '@auth0/auth0-react'
import TokenDisplay from './components/TokenDisplay'
import LoginButton from './components/LoginButton'
import LogoutButton from './components/LogoutButton'
import ApiCallButton from './components/ApiCallButton' // Import the new component
import RefreshTokenButton from './components/RefreshTokenButton'
import './App.css'

function App() {
  const { isAuthenticated, isLoading, error, user } = useAuth0()

  if (isLoading) {
    return <div className="loading">Loading Auth0 authentication...</div>
  }

  if (error) {
    return <div className="error">Authentication Error: {error.message}</div>
  }

  return (
    <div className="app-container">
      <h1>Auth0 Token Viewer</h1>
      
      {isAuthenticated ? (
        <div className="authenticated-container">
          <div className="user-info">
            <img 
              src={user.picture} 
              alt={user.name}
              className="profile-picture"
            />
            <h2>Welcome, {user.name}</h2>
            <p>{user.email}</p>
          </div>
          
          <TokenDisplay />
          <ApiCallButton /> {/* Add the API call button here */}
          <RefreshTokenButton /> {/* Add the refresh token button here */}
          <LogoutButton />
        </div>
      ) : (
        <div className="login-container">
          <p>Please log in to view your authentication tokens.</p>
          <LoginButton />
        </div>
      )}
    </div>
  )
}

export default App
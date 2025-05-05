import { useState, useEffect } from 'react'
import { useAuth0 } from '@auth0/auth0-react'
import { jwtDecode } from 'jwt-decode'

const TokenDisplay = () => {
  const { getAccessTokenSilently, isAuthenticated } = useAuth0()
  const [tokenData, setTokenData] = useState({
    accessToken: '',
    idToken: '',
    refreshToken: '', // Note: Auth0 doesn't directly expose refresh tokens
    decodedAccessToken: null,
    decodedIdToken: null
  })
  const [activeTab, setActiveTab] = useState('accessToken')

  useEffect(() => {
    const getTokens = async () => {
      if (isAuthenticated) {
        try {
          // Get access token with extra options to get id_token and refresh_token
          const accessToken = await getAccessTokenSilently({
            detailedResponse: true,
          })
          
          // The detailedResponse option returns an object with tokens
          setTokenData({
            accessToken: accessToken.access_token,
            idToken: accessToken.id_token,
            refreshToken: "Refresh tokens are not directly accessible for security reasons",
            decodedAccessToken: jwtDecode(accessToken.access_token),
            decodedIdToken: jwtDecode(accessToken.id_token)
          })
        } catch (error) {
          console.error('Error getting token data:', error)
        }
      }
    }

    getTokens()
  }, [getAccessTokenSilently, isAuthenticated])

  const renderToken = (token, decoded) => {
    if (!token) return <div>Loading token...</div>
    
    return (
      <div className="token-content">
        <div className="raw-token">
          <h4>Raw Token:</h4>
          <div className="token-box">{token}</div>
        </div>
        
        {decoded && (
          <div className="decoded-token">
            <h4>Decoded Token:</h4>
            <pre>{JSON.stringify(decoded, null, 2)}</pre>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="token-display">
      <div className="token-tabs">
        <button 
          className={activeTab === 'accessToken' ? 'active' : ''} 
          onClick={() => setActiveTab('accessToken')}
        >
          Access Token
        </button>
        <button 
          className={activeTab === 'idToken' ? 'active' : ''} 
          onClick={() => setActiveTab('idToken')}
        >
          ID Token
        </button>
        <button 
          className={activeTab === 'refreshToken' ? 'active' : ''} 
          onClick={() => setActiveTab('refreshToken')}
        >
          Refresh Token
        </button>
      </div>
      
      <div className="token-panel">
        {activeTab === 'accessToken' && renderToken(tokenData.accessToken, tokenData.decodedAccessToken)}
        {activeTab === 'idToken' && renderToken(tokenData.idToken, tokenData.decodedIdToken)}
        {activeTab === 'refreshToken' && (
          <div className="token-content">
            <div className="raw-token">
              <h4>Refresh Token:</h4>
              <div className="token-box">
                <p>{tokenData.refreshToken}</p>
                <p className="note">
                  Note: For security reasons, Auth0's JavaScript SDK does not expose refresh tokens directly to the frontend.
                  Refresh tokens should be handled server-side in a production application.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default TokenDisplay
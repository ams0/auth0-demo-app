import { useState } from "react";
import { useAuth0 } from "@auth0/auth0-react";

const RefreshTokenButton = () => {
  const { getAccessTokenSilently } = useAuth0();
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState("");

  const handleRefresh = async () => {
    setIsLoading(true);
    setMessage("");
    try {
      // Calling getAccessTokenSilently will attempt to retrieve a fresh token.
      // The SDK handles using the refresh token automatically if the access token is expired
      // and refresh tokens are enabled and available.
      // We include the audience and scope to ensure the refreshed token has the necessary permissions.
      const token = await getAccessTokenSilently({
        // Ensure these match your main.jsx configuration
        audience: "http://localhost:3000/api/v1/admin your-second-api-identifier", // Use the same space-separated audiences
        scope: "openid profile email offline_access",
        // Optionally, you could try ignoreCache, but the SDK usually handles expiry well.
        // ignoreCache: true,
      });
      // The TokenDisplay component should automatically update if it re-fetches
      // after a successful refresh, so we just show a success message here.
      setMessage("Token refresh attempted successfully.");
      console.log("Refreshed Token (first 10 chars):", token.substring(0, 10) + "...");
    } catch (error) {
      console.error("Error refreshing token:", error);
      setMessage(`Error refreshing token: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="refresh-token-section">
      <button
        className="auth-button refresh-button"
        onClick={handleRefresh}
        disabled={isLoading}
      >
        {isLoading ? "Refreshing Token..." : "Refresh Access Token"}
      </button>
      {message && <p className={`message ${message.startsWith("Error") ? 'error-message' : 'success-message'}`}>{message}</p>}
    </div>
  );
};

export default RefreshTokenButton;


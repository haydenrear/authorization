"use client";

import { useEffect, useState } from "react";
import styles from "./dashboard.module.css";

interface CreditsResponse {
  hasCredits: boolean;
  remaining: number;
  userId: string;
}

interface UserProfile {
  email: string;
  principalId: string;
  credits: CreditsResponse;
  jwtToken: string;
}

export default function Dashboard() {
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editMode, setEditMode] = useState(false);
  const [formData, setFormData] = useState({
    email: "",
    name: "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });
  const [showTokens, setShowTokens] = useState(false);
  const [tokenCopied, setTokenCopied] = useState(false);

  // Fetch user profile and credits
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem("jwtToken");

        if (!token) {
          setError("No authentication token found. Please login first.");
          setLoading(false);
          return;
        }

        // Fetch credits
        const creditsResponse = await fetch("/api/v1/credits/get-credits", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        if (!creditsResponse.ok) {
          throw new Error("Failed to fetch credits");
        }

        const credits = await creditsResponse.json();

        // Fetch user profile (we'll need to create this endpoint)
        const profileResponse = await fetch("/api/v1/user/profile", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        if (!profileResponse.ok) {
          throw new Error("Failed to fetch user profile");
        }

        const profile = await profileResponse.json();

        setUserProfile({
          email: profile.email,
          principalId: profile.principalId,
          credits,
          jwtToken: token,
        });

        setFormData({
          email: profile.email,
          name: profile.principalId,
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "An error occurred");
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!userProfile) return;

    try {
      // Validate passwords match
      if (
        formData.newPassword &&
        formData.newPassword !== formData.confirmPassword
      ) {
        setError("Passwords do not match");
        return;
      }

      const token = localStorage.getItem("jwtToken");
      if (!token) {
        setError("No authentication token found");
        return;
      }

      const updateData: Record<string, string> = {
        email: formData.email,
        name: formData.name,
      };

      if (formData.newPassword) {
        updateData.currentPassword = formData.currentPassword;
        updateData.newPassword = formData.newPassword;
      }

      const response = await fetch("/api/v1/user/profile", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(updateData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Failed to update profile");
      }

      const updatedProfile = await response.json();
      setUserProfile((prev) =>
        prev
          ? {
              ...prev,
              email: updatedProfile.email,
              principalId: updatedProfile.principalId,
            }
          : null,
      );

      setEditMode(false);
      setError(null);
      setFormData((prev) => ({
        ...prev,
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update profile");
    }
  };

  const handleCopyToken = () => {
    if (userProfile?.jwtToken) {
      navigator.clipboard.writeText(userProfile.jwtToken);
      setTokenCopied(true);
      setTimeout(() => setTokenCopied(false), 2000);
    }
  };

  const handleRevokeToken = async () => {
    if (!userProfile) return;

    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        setError("No authentication token found");
        return;
      }

      const response = await fetch("/api/v1/user/token/revoke", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("Failed to revoke token");
      }

      setError("Token revoked. Please login again.");
      localStorage.removeItem("jwtToken");
      setUserProfile(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke token");
    }
  };

  const handleGenerateNewToken = async () => {
    if (!userProfile) return;

    try {
      const token = localStorage.getItem("jwtToken");
      if (!token) {
        setError("No authentication token found");
        return;
      }

      const response = await fetch("/api/v1/user/token/generate", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        throw new Error("Failed to generate new token");
      }

      const newToken = await response.json();
      localStorage.setItem("jwtToken", newToken.token);
      setUserProfile((prev) =>
        prev
          ? {
              ...prev,
              jwtToken: newToken.token,
            }
          : null,
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to generate new token",
      );
    }
  };

  const handlePurchaseCredits = () => {
    // Redirect to Stripe payment link
    const stripeLink = process.env.NEXT_PUBLIC_STRIPE_PURCHASE_LINK;
    if (stripeLink) {
      // Add the user's email as a query parameter for pre-filling in Stripe
      const url = new URL(stripeLink);
      const token = localStorage.getItem("jwtToken");
      if (token && userProfile?.email) {
        url.searchParams.append("client_reference_id", userProfile.principalId);
        url.searchParams.append("prefilled_email", userProfile.email);
      }
      window.location.href = url.toString();
    } else {
      setError("Stripe payment link not configured");
    }
  };

  if (loading) {
    return (
      <div className={styles.container}>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  if (!userProfile) {
    return (
      <div className={styles.container}>
        <p>Error: {error || "Unable to load user profile"}</p>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h1>Dashboard</h1>
        <button
          className={styles.logoutBtn}
          onClick={() => {
            localStorage.removeItem("jwtToken");
            window.location.href = "/login";
          }}
        >
          Logout
        </button>
      </div>

      {error && <div className={styles.alert}>{error}</div>}

      {/* Credits Section */}
      <section className={styles.section}>
        <h2>Credits</h2>
        <div className={styles.creditsCard}>
          <div className={styles.creditAmount}>
            <span className={styles.label}>Available Credits:</span>
            <span className={styles.amount}>
              {userProfile.credits.remaining}
            </span>
          </div>
          <button className={styles.primaryBtn} onClick={handlePurchaseCredits}>
            Purchase Credits
          </button>
        </div>
      </section>

      {/* Profile Section */}
      <section className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>Profile Information</h2>
          <button
            className={styles.secondaryBtn}
            onClick={() => setEditMode(!editMode)}
          >
            {editMode ? "Cancel" : "Edit"}
          </button>
        </div>

        {editMode ? (
          <form onSubmit={handleUpdateProfile} className={styles.form}>
            <div className={styles.formGroup}>
              <label htmlFor="name">Name</label>
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
              />
            </div>

            <div className={styles.formGroup}>
              <label htmlFor="email">Email</label>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleInputChange}
                required
              />
            </div>

            <div className={styles.divider}>Change Password</div>

            <div className={styles.formGroup}>
              <label htmlFor="currentPassword">Current Password</label>
              <input
                type="password"
                id="currentPassword"
                name="currentPassword"
                value={formData.currentPassword}
                onChange={handleInputChange}
              />
            </div>

            <div className={styles.formGroup}>
              <label htmlFor="newPassword">New Password</label>
              <input
                type="password"
                id="newPassword"
                name="newPassword"
                value={formData.newPassword}
                onChange={handleInputChange}
              />
            </div>

            <div className={styles.formGroup}>
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                type="password"
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleInputChange}
              />
            </div>

            <button type="submit" className={styles.primaryBtn}>
              Save Changes
            </button>
          </form>
        ) : (
          <div className={styles.profileDisplay}>
            <div className={styles.profileItem}>
              <span className={styles.label}>Name:</span>
              <span className={styles.value}>{userProfile.principalId}</span>
            </div>
            <div className={styles.profileItem}>
              <span className={styles.label}>Email:</span>
              <span className={styles.value}>{userProfile.email}</span>
            </div>
          </div>
        )}
      </section>

      {/* API Token Section */}
      <section className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2>API Token</h2>
          <button
            className={styles.secondaryBtn}
            onClick={() => setShowTokens(!showTokens)}
          >
            {showTokens ? "Hide" : "Show"}
          </button>
        </div>

        <p className={styles.tokenInfo}>
          Your JWT token can be used as an API key for authentication. Keep it
          secure and do not share it.
        </p>

        {showTokens && (
          <div className={styles.tokenDisplay}>
            <div className={styles.tokenBox}>
              <code>{userProfile.jwtToken}</code>
            </div>
            <div className={styles.tokenActions}>
              <button className={styles.secondaryBtn} onClick={handleCopyToken}>
                {tokenCopied ? "Copied!" : "Copy Token"}
              </button>
              <button
                className={styles.dangerBtn}
                onClick={handleGenerateNewToken}
              >
                Generate New Token
              </button>
            </div>
          </div>
        )}

        <button
          className={styles.dangerBtn}
          onClick={handleRevokeToken}
          style={{ marginTop: "1rem" }}
        >
          Revoke Current Token
        </button>
      </section>
    </div>
  );
}

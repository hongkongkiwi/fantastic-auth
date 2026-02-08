/**
 * UserProfile Component
 * 
 * User profile screen for managing account details.
 * 
 * @example
 * ```tsx
 * <UserProfile
 *   onUpdate={(user) => console.log('Updated:', user)}
 * />
 * ```
 */

import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  Image,
} from 'react-native';
import { UserProfileProps } from '../types';
import { useUserManager } from '../hooks/useUser';

export function UserProfile({
  onUpdate,
  style,
  testID,
}: UserProfileProps) {
  const { user, isLoading, error, update, uploadAvatar } = useUserManager();
  
  const [name, setName] = useState(user?.profile?.name || '');
  const [isEditing, setIsEditing] = useState(false);
  const [updateError, setUpdateError] = useState<string | null>(null);
  
  if (!user) {
    return (
      <View style={[styles.container, style]} testID={testID}>
        <Text style={styles.notSignedInText}>
          Please sign in to view your profile.
        </Text>
      </View>
    );
  }
  
  const handleSave = async () => {
    try {
      setUpdateError(null);
      await update({ profile: { ...user.profile, name } });
      setIsEditing(false);
      onUpdate?.(user);
    } catch (err: any) {
      setUpdateError(err?.message || 'Failed to update profile');
    }
  };
  
  const handleAvatarUpload = async () => {
    // This would typically use react-native-image-picker
    // For now, it's a placeholder
    console.log('Avatar upload would be implemented here');
  };
  
  const getInitials = () => {
    if (user.profile?.name) {
      return user.profile.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);
    }
    return user.email?.slice(0, 2).toUpperCase() || '?';
  };
  
  return (
    <ScrollView style={[styles.container, style]} testID={testID}>
      <Text style={styles.title}>Profile</Text>
      
      {(error || updateError) && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>
            {error?.message || updateError}
          </Text>
        </View>
      )}
      
      <View style={styles.avatarSection}>
        {user.profile?.picture ? (
          <Image source={{ uri: user.profile.picture }} style={styles.avatar} />
        ) : (
          <View style={styles.avatarPlaceholder}>
            <Text style={styles.avatarText}>{getInitials()}</Text>
          </View>
        )}
        <TouchableOpacity onPress={handleAvatarUpload}>
          <Text style={styles.changeAvatarText}>Change Avatar</Text>
        </TouchableOpacity>
      </View>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Email</Text>
        <Text style={styles.emailText}>{user.email}</Text>
        {user.emailVerified ? (
          <Text style={styles.verifiedText}>✓ Verified</Text>
        ) : (
          <Text style={styles.unverifiedText}>✗ Not verified</Text>
        )}
      </View>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Name</Text>
        {isEditing ? (
          <View>
            <TextInput
              style={styles.input}
              value={name}
              onChangeText={setName}
              placeholder="Your name"
              autoFocus
            />
            <View style={styles.editButtons}>
              <TouchableOpacity
                style={[styles.button, styles.secondaryButton]}
                onPress={() => {
                  setName(user.profile?.name || '');
                  setIsEditing(false);
                }}
              >
                <Text style={styles.secondaryButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.button, styles.primaryButton]}
                onPress={handleSave}
                disabled={isLoading}
              >
                {isLoading ? (
                  <ActivityIndicator color="#fff" size="small" />
                ) : (
                  <Text style={styles.buttonText}>Save</Text>
                )}
              </TouchableOpacity>
            </View>
          </View>
        ) : (
          <TouchableOpacity onPress={() => setIsEditing(true)}>
            <Text style={styles.nameText}>
              {user.profile?.name || 'Add name'}
            </Text>
            <Text style={styles.editHint}>Tap to edit</Text>
          </TouchableOpacity>
        )}
      </View>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Account</Text>
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Status</Text>
          <Text style={styles.infoValue}>{user.status}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.infoLabel}>Member since</Text>
          <Text style={styles.infoValue}>
            {new Date(user.createdAt).toLocaleDateString()}
          </Text>
        </View>
        {user.lastLoginAt && (
          <View style={styles.infoRow}>
            <Text style={styles.infoLabel}>Last login</Text>
            <Text style={styles.infoValue}>
              {new Date(user.lastLoginAt).toLocaleString()}
            </Text>
          </View>
        )}
      </View>
      
      {user.mfaEnabled && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Security</Text>
          <View style={styles.infoRow}>
            <Text style={styles.infoLabel}>MFA</Text>
            <Text style={styles.infoValue}>Enabled</Text>
          </View>
          <Text style={styles.mfaMethods}>
            Methods: {user.mfaMethods.join(', ')}
          </Text>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    marginBottom: 24,
  },
  notSignedInText: {
    fontSize: 16,
    textAlign: 'center',
    color: '#666',
    marginTop: 40,
  },
  errorContainer: {
    backgroundColor: '#ffebee',
    padding: 12,
    borderRadius: 8,
    marginBottom: 16,
  },
  errorText: {
    color: '#c62828',
    fontSize: 14,
  },
  avatarSection: {
    alignItems: 'center',
    marginBottom: 32,
  },
  avatar: {
    width: 100,
    height: 100,
    borderRadius: 50,
    marginBottom: 12,
  },
  avatarPlaceholder: {
    width: 100,
    height: 100,
    borderRadius: 50,
    backgroundColor: '#333',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 12,
  },
  avatarText: {
    color: '#fff',
    fontSize: 36,
    fontWeight: '600',
  },
  changeAvatarText: {
    color: '#0066cc',
    fontSize: 16,
  },
  section: {
    marginBottom: 24,
    paddingBottom: 24,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: '600',
    color: '#666',
    marginBottom: 8,
    textTransform: 'uppercase',
  },
  emailText: {
    fontSize: 16,
    color: '#333',
  },
  verifiedText: {
    color: '#2e7d32',
    fontSize: 14,
    marginTop: 4,
  },
  unverifiedText: {
    color: '#c62828',
    fontSize: 14,
    marginTop: 4,
  },
  nameText: {
    fontSize: 18,
    color: '#333',
  },
  editHint: {
    color: '#666',
    fontSize: 12,
    marginTop: 4,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    backgroundColor: '#fafafa',
    marginBottom: 12,
  },
  editButtons: {
    flexDirection: 'row',
    gap: 12,
  },
  button: {
    flex: 1,
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  primaryButton: {
    backgroundColor: '#000',
  },
  secondaryButton: {
    backgroundColor: '#f5f5f5',
    borderWidth: 1,
    borderColor: '#ddd',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  secondaryButtonText: {
    color: '#333',
    fontSize: 16,
    fontWeight: '600',
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  infoLabel: {
    fontSize: 14,
    color: '#666',
  },
  infoValue: {
    fontSize: 14,
    color: '#333',
    fontWeight: '500',
  },
  mfaMethods: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
});

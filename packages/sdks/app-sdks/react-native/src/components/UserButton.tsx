/**
 * UserButton Component
 * 
 * User avatar button with dropdown menu.
 * 
 * @example
 * ```tsx
 * <UserButton
 *   showName={true}
 *   onSignOut={() => navigation.navigate('SignIn')}
 *   menuItems={[
 *     { label: 'Settings', onPress: () => navigation.navigate('Settings') },
 *   ]}
 * />
 * ```
 */

import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Modal,
  Image,
  Dimensions,
} from 'react-native';
import { UserButtonProps } from '../types';
import { useAuth } from '../hooks/useAuth';
import { useUser } from '../hooks/useUser';

const { width } = Dimensions.get('window');

export function UserButton({
  showName = false,
  avatarUrl,
  onSignOut,
  menuItems = [],
  showManageAccount = true,
  style,
  testID,
}: UserButtonProps) {
  const [menuVisible, setMenuVisible] = useState(false);
  const { signOut } = useAuth();
  const user = useUser();
  
  const handleSignOut = async () => {
    setMenuVisible(false);
    await signOut();
    onSignOut?.();
  };
  
  const getInitials = () => {
    if (user?.profile?.name) {
      return user.profile.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);
    }
    return user?.email?.slice(0, 2).toUpperCase() || '?';
  };
  
  return (
    <View style={style} testID={testID}>
      <TouchableOpacity
        style={styles.button}
        onPress={() => setMenuVisible(true)}
      >
        {avatarUrl ? (
          <Image source={{ uri: avatarUrl }} style={styles.avatar} />
        ) : (
          <View style={styles.avatarPlaceholder}>
            <Text style={styles.avatarText}>{getInitials()}</Text>
          </View>
        )}
        
        {showName && (
          <Text style={styles.nameText} numberOfLines={1}>
            {user?.profile?.name || user?.email}
          </Text>
        )}
      </TouchableOpacity>
      
      <Modal
        visible={menuVisible}
        transparent
        animationType="fade"
        onRequestClose={() => setMenuVisible(false)}
      >
        <TouchableOpacity
          style={styles.overlay}
          activeOpacity={1}
          onPress={() => setMenuVisible(false)}
        >
          <View style={styles.menu}>
            {user && (
              <View style={styles.userInfo}>
                <Text style={styles.userEmail}>{user.email}</Text>
              </View>
            )}
            
            {showManageAccount && (
              <TouchableOpacity
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  // Navigate to manage account
                }}
              >
                <Text style={styles.menuItemText}>Manage Account</Text>
              </TouchableOpacity>
            )}
            
            {menuItems.map((item, index) => (
              <TouchableOpacity
                key={index}
                style={styles.menuItem}
                onPress={() => {
                  setMenuVisible(false);
                  item.onPress();
                }}
              >
                <Text style={styles.menuItemText}>{item.label}</Text>
              </TouchableOpacity>
            ))}
            
            <View style={styles.divider} />
            
            <TouchableOpacity
              style={[styles.menuItem, styles.signOutItem]}
              onPress={handleSignOut}
            >
              <Text style={[styles.menuItemText, styles.signOutText]}>
                Sign Out
              </Text>
            </TouchableOpacity>
          </View>
        </TouchableOpacity>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  button: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 8,
  },
  avatar: {
    width: 36,
    height: 36,
    borderRadius: 18,
  },
  avatarPlaceholder: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: '#333',
    alignItems: 'center',
    justifyContent: 'center',
  },
  avatarText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '600',
  },
  nameText: {
    marginLeft: 8,
    fontSize: 14,
    fontWeight: '500',
    maxWidth: 150,
  },
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    justifyContent: 'flex-start',
    alignItems: 'flex-end',
    paddingTop: 60,
    paddingRight: 16,
  },
  menu: {
    backgroundColor: '#fff',
    borderRadius: 12,
    minWidth: 200,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 4,
    elevation: 5,
  },
  userInfo: {
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  userEmail: {
    fontSize: 14,
    fontWeight: '600',
    color: '#333',
  },
  menuItem: {
    padding: 16,
  },
  menuItemText: {
    fontSize: 16,
    color: '#333',
  },
  divider: {
    height: 1,
    backgroundColor: '#eee',
  },
  signOutItem: {
    borderBottomLeftRadius: 12,
    borderBottomRightRadius: 12,
  },
  signOutText: {
    color: '#c62828',
  },
});

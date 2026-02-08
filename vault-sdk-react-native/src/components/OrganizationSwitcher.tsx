/**
 * OrganizationSwitcher Component
 * 
 * Organization selection and switching component.
 * 
 * @example
 * ```tsx
 * <OrganizationSwitcher
 *   onSwitch={(org) => console.log('Switched to:', org?.name)}
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
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { OrganizationSwitcherProps } from '../types';
import { useOrganization, useAuth } from '../hooks';

export function OrganizationSwitcher({
  hidePersonal = false,
  onSwitch,
  style,
  testID,
}: OrganizationSwitcherProps) {
  const [modalVisible, setModalVisible] = useState(false);
  const { organization, organizations, isLoaded, isLoading, setActive } = useOrganization();
  const { user } = useAuth();
  
  const handleSelect = async (orgId: string | null) => {
    try {
      await setActive(orgId);
      const selectedOrg = orgId ? organizations.find(o => o.id === orgId) || null : null;
      onSwitch?.(selectedOrg);
    } finally {
      setModalVisible(false);
    }
  };
  
  if (!isLoaded) {
    return (
      <View style={[styles.container, style]} testID={testID}>
        <ActivityIndicator size="small" />
      </View>
    );
  }
  
  return (
    <View style={style} testID={testID}>
      <TouchableOpacity
        style={styles.selector}
        onPress={() => setModalVisible(true)}
      >
        <View style={styles.orgInfo}>
          {organization?.logoUrl ? (
            <View style={styles.logoPlaceholder}>
              <Text style={styles.logoText}>
                {organization.name.charAt(0)}
              </Text>
            </View>
          ) : (
            <View style={styles.logoPlaceholder}>
              <Text style={styles.logoText}>
                {organization?.name?.charAt(0) || user?.email?.charAt(0) || '?'}
              </Text>
            </View>
          )}
          <View style={styles.textContainer}>
            <Text style={styles.orgName} numberOfLines={1}>
              {organization?.name || 'Personal Account'}
            </Text>
            {organization && (
              <Text style={styles.roleText}>
                {organization.role}
              </Text>
            )}
          </View>
        </View>
        <Text style={styles.chevron}>▼</Text>
      </TouchableOpacity>
      
      <Modal
        visible={modalVisible}
        transparent
        animationType="slide"
        onRequestClose={() => setModalVisible(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>Select Organization</Text>
              <TouchableOpacity onPress={() => setModalVisible(false)}>
                <Text style={styles.closeButton}>✕</Text>
              </TouchableOpacity>
            </View>
            
            <ScrollView style={styles.orgList}>
              {!hidePersonal && (
                <TouchableOpacity
                  style={[
                    styles.orgItem,
                    !organization && styles.selectedOrgItem,
                  ]}
                  onPress={() => handleSelect(null)}
                >
                  <View style={styles.orgItemLogo}>
                    <Text style={styles.orgItemLogoText}>
                      {user?.email?.charAt(0).toUpperCase() || '?'}
                    </Text>
                  </View>
                  <View style={styles.orgItemInfo}>
                    <Text style={styles.orgItemName}>Personal Account</Text>
                    <Text style={styles.orgItemEmail}>{user?.email}</Text>
                  </View>
                  {!organization && <Text style={styles.checkmark}>✓</Text>}
                </TouchableOpacity>
              )}
              
              {organizations.map((org) => (
                <TouchableOpacity
                  key={org.id}
                  style={[
                    styles.orgItem,
                    organization?.id === org.id && styles.selectedOrgItem,
                  ]}
                  onPress={() => handleSelect(org.id)}
                >
                  <View style={styles.orgItemLogo}>
                    <Text style={styles.orgItemLogoText}>
                      {org.name.charAt(0).toUpperCase()}
                    </Text>
                  </View>
                  <View style={styles.orgItemInfo}>
                    <Text style={styles.orgItemName}>{org.name}</Text>
                    <Text style={styles.orgItemRole}>{org.role}</Text>
                  </View>
                  {organization?.id === org.id && (
                    <Text style={styles.checkmark}>✓</Text>
                  )}
                </TouchableOpacity>
              ))}
            </ScrollView>
            
            {isLoading && (
              <View style={styles.loadingOverlay}>
                <ActivityIndicator />
              </View>
            )}
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 12,
  },
  selector: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 12,
    backgroundColor: '#f5f5f5',
    borderRadius: 8,
  },
  orgInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  logoPlaceholder: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: '#333',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  logoText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  textContainer: {
    flex: 1,
  },
  orgName: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
  },
  roleText: {
    fontSize: 12,
    color: '#666',
    textTransform: 'capitalize',
  },
  chevron: {
    fontSize: 12,
    color: '#666',
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    justifyContent: 'flex-end',
  },
  modalContent: {
    backgroundColor: '#fff',
    borderTopLeftRadius: 16,
    borderTopRightRadius: 16,
    maxHeight: '70%',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  modalTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  closeButton: {
    fontSize: 20,
    color: '#666',
    padding: 4,
  },
  orgList: {
    maxHeight: 400,
  },
  orgItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#f5f5f5',
  },
  selectedOrgItem: {
    backgroundColor: '#f0f7ff',
  },
  orgItemLogo: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#333',
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 12,
  },
  orgItemLogoText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  orgItemInfo: {
    flex: 1,
  },
  orgItemName: {
    fontSize: 16,
    fontWeight: '500',
    color: '#333',
  },
  orgItemEmail: {
    fontSize: 13,
    color: '#666',
  },
  orgItemRole: {
    fontSize: 13,
    color: '#666',
    textTransform: 'capitalize',
  },
  checkmark: {
    fontSize: 18,
    color: '#0066cc',
    fontWeight: '600',
  },
  loadingOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(255, 255, 255, 0.8)',
    alignItems: 'center',
    justifyContent: 'center',
  },
});

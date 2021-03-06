import React from 'react';
import { API } from 'foremanReact/redux/API';
import { addToast } from 'foremanReact/redux/actions/toasts';
import { inventoryUrl } from '../../../../ForemanInventoryHelpers';
import Toast from './components/Toast';
import {
  INVENTORY_SYNC_REQUEST,
  INVENTORY_SYNC_SUCCESS,
  INVENTORY_SYNC_ERROR,
} from './SyncButtonConstants';

export const handleSync = () => async dispatch => {
  dispatch({
    type: INVENTORY_SYNC_REQUEST,
    payload: {},
  });
  try {
    const {
      data: { syncHosts, disconnectHosts },
    } = await API.post(inventoryUrl('tasks'));
    dispatch({
      type: INVENTORY_SYNC_SUCCESS,
      payload: {
        syncHosts,
        disconnectHosts,
      },
    });

    dispatch(
      addToast({
        sticky: true,
        type: 'success',
        message: (
          <Toast syncHosts={syncHosts} disconnectHosts={disconnectHosts} />
        ),
      })
    );
  } catch ({
    message,
    response: { data: { message: toastMessage } = {} } = {},
  }) {
    dispatch({
      type: INVENTORY_SYNC_ERROR,
      payload: {
        error: message,
      },
    });

    dispatch(
      addToast({
        sticky: true,
        type: 'error',
        message: toastMessage || message,
      })
    );
  }
};

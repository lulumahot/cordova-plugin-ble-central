// (c) 2014-2016 Don Coleman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.megster.cordova.ble.central;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothManager;

import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.annotation.TargetApi;
import android.os.ParcelUuid;



import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.Build;

import android.net.Uri;

import android.provider.Settings;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.LOG;
import org.apache.cordova.PermissionHelper;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.util.*;

public class BLECentralPlugin extends CordovaPlugin  implements BluetoothAdapter.LeScanCallback{
    // actions
    private static final String SCAN = "scan";
    private static final String START_SCAN = "startScan";
    private static final String STOP_SCAN = "stopScan";
    private static final String START_SCAN_WITH_OPTIONS = "startScanWithOptions";

    private static final String LIST = "list";

    private static final String CONNECT = "connect";
    private static final String AUTOCONNECT = "autoConnect";
    private static final String DISCONNECT = "disconnect";

    private static final String REQUEST_MTU = "requestMtu";

    private static final String READ = "read";
    private static final String WRITE = "write";
    private static final String WRITE_WITHOUT_RESPONSE = "writeWithoutResponse";

    private static final String READ_RSSI = "readRSSI";

    private static final String START_NOTIFICATION = "startNotification"; // register for characteristic notification
    private static final String STOP_NOTIFICATION = "stopNotification"; // remove characteristic notification

    private static final String IS_ENABLED = "isEnabled";
    private static final String IS_CONNECTED  = "isConnected";

    private static final String SETTINGS = "showBluetoothSettings";
    private static final String ENABLE = "enable";

    private static final String START_STATE_NOTIFICATIONS = "startStateNotifications";
    private static final String STOP_STATE_NOTIFICATIONS = "stopStateNotifications";

    private static final String UPGRADE_FIRMWARE = "upgradeFirmware";

    // callbacks
    CallbackContext discoverCallback;
    private CallbackContext enableBluetoothCallback;

    private static final String TAG = "BLEPlugin";
    private static final int REQUEST_ENABLE_BLUETOOTH = 1;

    BluetoothAdapter bluetoothAdapter;

    // key is the MAC Address
    Map<String, Peripheral> peripherals = new LinkedHashMap<String, Peripheral>();

    // scan options
    boolean reportDuplicates = false;

    // Android 23 requires new permissions for BluetoothLeScanner.startScan()
    private static final String ACCESS_COARSE_LOCATION = Manifest.permission.ACCESS_COARSE_LOCATION;
    private static final int REQUEST_ACCESS_COARSE_LOCATION = 2;
    private static final int PERMISSION_DENIED_ERROR = 20;
    private CallbackContext permissionCallback;
    private UUID[] serviceUUIDs;
    private int scanSeconds;

    //private 
    private ArrayList<ScanFilter> filters = new ArrayList();
    private BluetoothLeScanner bluetoothLeScanner;


    // Bluetooth state notification
    CallbackContext stateCallback;
    BroadcastReceiver stateReceiver;
    Map<Integer, String> bluetoothStates = new Hashtable<Integer, String>() {{
        put(BluetoothAdapter.STATE_OFF, "off");
        put(BluetoothAdapter.STATE_TURNING_OFF, "turningOff");
        put(BluetoothAdapter.STATE_ON, "on");
        put(BluetoothAdapter.STATE_TURNING_ON, "turningOn");
    }};

    public void onDestroy() {
        removeStateListener();
    }

    public void onReset() {
        removeStateListener();
    }

    @Override
    public boolean execute(String action, CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        LOG.d(TAG, "action = " + action);

        if (bluetoothAdapter == null) {
            Activity activity = cordova.getActivity();
            boolean hardwareSupportsBLE = activity.getApplicationContext()
                                            .getPackageManager()
                                            .hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) &&
                                            Build.VERSION.SDK_INT >= 18;
            if (!hardwareSupportsBLE) {
              LOG.w(TAG, "This hardware does not support Bluetooth Low Energy.");
              callbackContext.error("This hardware does not support Bluetooth Low Energy.");
              return false;
            }
            BluetoothManager bluetoothManager = (BluetoothManager) activity.getSystemService(Context.BLUETOOTH_SERVICE);
            bluetoothAdapter = bluetoothManager.getAdapter();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                bluetoothLeScanner = bluetoothAdapter.getBluetoothLeScanner();
            }
        }

        boolean validAction = true;

        if (action.equals(SCAN)) {

            if(Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP){
                UUID[] serviceUUIDs = parseServiceUUIDList(args.getJSONArray(0));
                int scanSeconds = args.getInt(1);
                resetScanOptions();
                findLowEnergyDevices(callbackContext, serviceUUIDs, scanSeconds);
            }else{
                ArrayList<ScanFilter> filters = parseServiceUUIDListAsFilters(args.getJSONArray(0));
                int scanSeconds = args.getInt(1);
                resetScanOptions();
                findLowEnergyDevicesNewWay(callbackContext, filters, scanSeconds);
            }

        } else if (action.equals(START_SCAN)) {

            if(Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP){
                UUID[] serviceUUIDs = parseServiceUUIDList(args.getJSONArray(0));
                resetScanOptions();
                findLowEnergyDevices(callbackContext, serviceUUIDs, -1);
            }else{
                ArrayList<ScanFilter> filters = parseServiceUUIDListAsFilters(args.getJSONArray(0));
                resetScanOptions();
                findLowEnergyDevicesNewWay(callbackContext, filters, -1);
            }

        } else if (action.equals(STOP_SCAN)) {

            bluetoothAdapter.stopLeScan(this);
            callbackContext.success();

        } else if (action.equals(LIST)) {

            listKnownDevices(callbackContext);

        } else if (action.equals(CONNECT)) {

            String macAddress = args.getString(0);
            connect(callbackContext, macAddress);

        } else if (action.equals(AUTOCONNECT)) {

            String macAddress = args.getString(0);
            autoConnect(callbackContext, macAddress);

        } else if (action.equals(DISCONNECT)) {

            String macAddress = args.getString(0);
            disconnect(callbackContext, macAddress);

        } else if (action.equals(REQUEST_MTU)) {

            String macAddress = args.getString(0);
            int mtuValue = args.getInt(1);
            requestMtu(callbackContext, macAddress, mtuValue);

        } else if (action.equals(READ)) {

            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            read(callbackContext, macAddress, serviceUUID, characteristicUUID);

        } else if (action.equals(READ_RSSI)) {

            String macAddress = args.getString(0);
            readRSSI(callbackContext, macAddress);

        } else if (action.equals(WRITE)) {

            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            byte[] data = args.getArrayBuffer(3);
            int type = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT;
            write(callbackContext, macAddress, serviceUUID, characteristicUUID, data, type);

        } else if (action.equals(WRITE_WITHOUT_RESPONSE)) {

            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            byte[] data = args.getArrayBuffer(3);
            int type = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE;
            write(callbackContext, macAddress, serviceUUID, characteristicUUID, data, type);

        } else if (action.equals(START_NOTIFICATION)) {

            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            registerNotifyCallback(callbackContext, macAddress, serviceUUID, characteristicUUID);

        } else if (action.equals(STOP_NOTIFICATION)) {

            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            removeNotifyCallback(callbackContext, macAddress, serviceUUID, characteristicUUID);

        } else if (action.equals(IS_ENABLED)) {

            if (bluetoothAdapter.isEnabled()) {
                callbackContext.success();
            } else {
                callbackContext.error("Bluetooth is disabled.");
            }

        } else if (action.equals(IS_CONNECTED)) {

            String macAddress = args.getString(0);

            if (peripherals.containsKey(macAddress) && peripherals.get(macAddress).isConnected()) {
                callbackContext.success();
            } else {
                callbackContext.error("Not connected.");
            }

        } else if (action.equals(SETTINGS)) {

            Intent intent = new Intent(Settings.ACTION_BLUETOOTH_SETTINGS);
            cordova.getActivity().startActivity(intent);
            callbackContext.success();

        } else if (action.equals(ENABLE)) {

            enableBluetoothCallback = callbackContext;
            Intent intent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            cordova.startActivityForResult(this, intent, REQUEST_ENABLE_BLUETOOTH);

        } else if (action.equals(START_STATE_NOTIFICATIONS)) {

            if (this.stateCallback != null) {
                callbackContext.error("State callback already registered.");
            } else {
                this.stateCallback = callbackContext;
                addStateListener();
                sendBluetoothStateChange(bluetoothAdapter.getState());
            }

        } else if (action.equals(STOP_STATE_NOTIFICATIONS)) {

            if (this.stateCallback != null) {
                // Clear callback in JavaScript without actually calling it
                PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                result.setKeepCallback(false);
                this.stateCallback.sendPluginResult(result);
                this.stateCallback = null;
            }
            removeStateListener();
            callbackContext.success();

        } else if (action.equals(UPGRADE_FIRMWARE)) {

            String macAddress = args.getString(0);
            Uri uri = Uri.parse(args.getString(1));
            int type = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT;
            upgradeFirmware(callbackContext, macAddress, uri);

        } else if (action.equals(START_SCAN_WITH_OPTIONS)) {

            LOG.d(TAG, "Android version " + Build.VERSION.SDK_INT);
            if(Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP){
                
                LOG.d(TAG, "Old ble handling");
                UUID[] serviceUUIDs = parseServiceUUIDList(args.getJSONArray(0));
                JSONObject options = args.getJSONObject(1);
                resetScanOptions();
                this.reportDuplicates = options.optBoolean("reportDuplicates", false);
                findLowEnergyDevices(callbackContext, serviceUUIDs, -1);

            }else{

                LOG.d(TAG, "New ble handling");
                ArrayList<ScanFilter> filters = parseServiceUUIDListAsFilters(args.getJSONArray(0));
                JSONObject options = args.getJSONObject(1);
                resetScanOptions();
                this.reportDuplicates = options.optBoolean("reportDuplicates", false);
                findLowEnergyDevicesNewWay(callbackContext, filters, -1);

            }

        } else {

            validAction = false;

        }

        return validAction;
    }

    private UUID[] parseServiceUUIDList(JSONArray jsonArray) throws JSONException {
        List<UUID> serviceUUIDs = new ArrayList<UUID>();

        for(int i = 0; i < jsonArray.length(); i++){
            String uuidString = jsonArray.getString(i);
            serviceUUIDs.add(uuidFromString(uuidString));
        }

        return serviceUUIDs.toArray(new UUID[jsonArray.length()]);
    }

    private ArrayList<ScanFilter> parseServiceUUIDListAsFilters(JSONArray jsonArray) throws JSONException {
        ArrayList<ScanFilter> filters = new ArrayList<ScanFilter>();

        for(int i = 0; i < jsonArray.length(); i++){
            String uuidString = jsonArray.getString(i);
            filters.add(new ScanFilter.Builder()
                    .setServiceUuid(ParcelUuid.fromString(uuidString))
                    .build());
        }

        return filters;
    }

    private void onBluetoothStateChange(Intent intent) {
        final String action = intent.getAction();

        if (action.equals(BluetoothAdapter.ACTION_STATE_CHANGED)) {
            final int state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR);
            sendBluetoothStateChange(state);
        }
    }

    private void sendBluetoothStateChange(int state) {
        if (this.stateCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, this.bluetoothStates.get(state));
            result.setKeepCallback(true);
            this.stateCallback.sendPluginResult(result);
        }
    }

    private void addStateListener() {
        if (this.stateReceiver == null) {
            this.stateReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    onBluetoothStateChange(intent);
                }
            };
        }

        try {
            IntentFilter intentFilter = new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED);
            webView.getContext().registerReceiver(this.stateReceiver, intentFilter);
        } catch (Exception e) {
            LOG.e(TAG, "Error registering state receiver: " + e.getMessage(), e);
        }
    }

    private void removeStateListener() {
        if (this.stateReceiver != null) {
            try {
                webView.getContext().unregisterReceiver(this.stateReceiver);
            } catch (Exception e) {
                LOG.e(TAG, "Error unregistering state receiver: " + e.getMessage(), e);
            }
        }
        this.stateCallback = null;
        this.stateReceiver = null;
    }

    private void connect(CallbackContext callbackContext, String macAddress) {
        if (!peripherals.containsKey(macAddress) && BLECentralPlugin.this.bluetoothAdapter.checkBluetoothAddress(macAddress)) {
            BluetoothDevice device = BLECentralPlugin.this.bluetoothAdapter.getRemoteDevice(macAddress);
            Peripheral peripheral = new Peripheral(device);
            peripherals.put(macAddress, peripheral);
        }

        Peripheral peripheral = peripherals.get(macAddress);
        if (peripheral != null) {
            peripheral.connect(callbackContext, cordova.getActivity(), false);
        } else {
            callbackContext.error("Peripheral " + macAddress + " not found.");
        }

    }

    private void autoConnect(CallbackContext callbackContext, String macAddress) {
        Peripheral peripheral = peripherals.get(macAddress);

        // allow auto-connect to connect to devices without scanning
        if (peripheral == null) {
            if (BluetoothAdapter.checkBluetoothAddress(macAddress)) {
                BluetoothDevice device = bluetoothAdapter.getRemoteDevice(macAddress);
                peripheral = new Peripheral(device);
                peripherals.put(device.getAddress(), peripheral);
            } else {
                callbackContext.error(macAddress + " is not a valid MAC address.");
                return;
            }
        }

        peripheral.connect(callbackContext, cordova.getActivity(), true);

    }

    private void disconnect(CallbackContext callbackContext, String macAddress) {

        Peripheral peripheral = peripherals.get(macAddress);
        if (peripheral != null) {
            peripheral.disconnect();
        }
        callbackContext.success();

    }

    private void requestMtu(CallbackContext callbackContext, String macAddress, int mtuValue) {

        Peripheral peripheral = peripherals.get(macAddress);
        if (peripheral != null) {
            peripheral.requestMtu(mtuValue);
        }
        callbackContext.success();

    }

    private void read(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID) {

        Peripheral peripheral = peripherals.get(macAddress);

        if (peripheral == null) {
            callbackContext.error("Peripheral " + macAddress + " not found.");
            return;
        }

        if (!peripheral.isConnected()) {
            callbackContext.error("Peripheral " + macAddress + " is not connected.");
            return;
        }

        //peripheral.readCharacteristic(callbackContext, serviceUUID, characteristicUUID);
        peripheral.queueRead(callbackContext, serviceUUID, characteristicUUID);

    }

    private void readRSSI(CallbackContext callbackContext, String macAddress) {

        Peripheral peripheral = peripherals.get(macAddress);

        if (peripheral == null) {
            callbackContext.error("Peripheral " + macAddress + " not found.");
            return;
        }

        if (!peripheral.isConnected()) {
            callbackContext.error("Peripheral " + macAddress + " is not connected.");
            return;
        }
        peripheral.queueReadRSSI(callbackContext);
    }

    private void write(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID,
                       byte[] data, int writeType) {

        Peripheral peripheral = peripherals.get(macAddress);

        if (peripheral == null) {
            callbackContext.error("Peripheral " + macAddress + " not found.");
            return;
        }

        if (!peripheral.isConnected()) {
            callbackContext.error("Peripheral " + macAddress + " is not connected.");
            return;
        }

        //peripheral.writeCharacteristic(callbackContext, serviceUUID, characteristicUUID, data, writeType);
        peripheral.queueWrite(callbackContext, serviceUUID, characteristicUUID, data, writeType);

    }

    private void registerNotifyCallback(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID) {

        Peripheral peripheral = peripherals.get(macAddress);
        if (peripheral != null) {

            if (!peripheral.isConnected()) {
                callbackContext.error("Peripheral " + macAddress + " is not connected.");
                return;
            }

            //peripheral.setOnDataCallback(serviceUUID, characteristicUUID, callbackContext);
            peripheral.queueRegisterNotifyCallback(callbackContext, serviceUUID, characteristicUUID);

        } else {

            callbackContext.error("Peripheral " + macAddress + " not found");

        }

    }

    private void removeNotifyCallback(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID) {

        Peripheral peripheral = peripherals.get(macAddress);
        if (peripheral != null) {

            if (!peripheral.isConnected()) {
                callbackContext.error("Peripheral " + macAddress + " is not connected.");
                return;
            }

            peripheral.queueRemoveNotifyCallback(callbackContext, serviceUUID, characteristicUUID);

        } else {

            callbackContext.error("Peripheral " + macAddress + " not found");

        }

    }

    private void findLowEnergyDevices(CallbackContext callbackContext, UUID[] serviceUUIDs, int scanSeconds) {

        if(!PermissionHelper.hasPermission(this, ACCESS_COARSE_LOCATION)) {
            // save info so we can call this method again after permissions are granted
            permissionCallback = callbackContext;
            this.serviceUUIDs = serviceUUIDs;
            this.scanSeconds = scanSeconds;
            PermissionHelper.requestPermission(this, REQUEST_ACCESS_COARSE_LOCATION, ACCESS_COARSE_LOCATION);
            return;
        }

        // return error if already scanning
        if (bluetoothAdapter.isDiscovering()) {
            LOG.w(TAG, "Tried to start scan while already running.");
            callbackContext.error("Tried to start scan while already running.");
            return;
        }

        // clear non-connected cached peripherals
        for(Iterator<Map.Entry<String, Peripheral>> iterator = peripherals.entrySet().iterator(); iterator.hasNext(); ) {
            Map.Entry<String, Peripheral> entry = iterator.next();
            Peripheral device = entry.getValue();
            boolean connecting = device.isConnecting();
            if (connecting){
                LOG.d(TAG, "Not removing connecting device: " + device.getDevice().getAddress());
            }
            if(!entry.getValue().isConnected() && !connecting) {
                iterator.remove();
            }
        }

        discoverCallback = callbackContext;

        if (serviceUUIDs != null && serviceUUIDs.length > 0) {
            bluetoothAdapter.startLeScan(serviceUUIDs, this);
        } else {
            bluetoothAdapter.startLeScan(this);
        }

        if (scanSeconds > 0) {
            Handler handler = new Handler();
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    LOG.d(TAG, "Stopping Scan");
                    BLECentralPlugin.this.bluetoothAdapter.stopLeScan(BLECentralPlugin.this);
                }
            }, scanSeconds * 1000);
        }

        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
        result.setKeepCallback(true);
        callbackContext.sendPluginResult(result);
    }

    private void findLowEnergyDevicesNewWay(CallbackContext callbackContext, ArrayList<ScanFilter> filters, int scanSeconds){
        if(!PermissionHelper.hasPermission(this, ACCESS_COARSE_LOCATION)) {
            // save info so we can call this method again after permissions are granted
            permissionCallback = callbackContext;
            this.filters = filters;
            this.scanSeconds = scanSeconds;
            PermissionHelper.requestPermission(this, REQUEST_ACCESS_COARSE_LOCATION, ACCESS_COARSE_LOCATION);
            return;
        }

        // return error if already scanning
        if (bluetoothAdapter.isDiscovering()) {
            LOG.w(TAG, "Tried to start scan while already running.");
            callbackContext.error("Tried to start scan while already running.");
            return;
        }

        // clear non-connected cached peripherals
        for(Iterator<Map.Entry<String, Peripheral>> iterator = peripherals.entrySet().iterator(); iterator.hasNext(); ) {
            Map.Entry<String, Peripheral> entry = iterator.next();
            Peripheral device = entry.getValue();
            boolean connecting = device.isConnecting();
            if (connecting){
                LOG.d(TAG, "Not removing connecting device: " + device.getDevice().getAddress());
            }
            if(!entry.getValue().isConnected() && !connecting) {
                iterator.remove();
            }
        }

        discoverCallback = callbackContext;
        ScanSettings settings = new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).setReportDelay(0).build();
        final ScanCallback scanCallback = new ScanCallback() {
            @TargetApi(Build.VERSION_CODES.LOLLIPOP)
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                onLeDeviceScanned(result.getDevice(), result.getRssi(), (result.getScanRecord() != null) ? result.getScanRecord().getBytes() : null);
            }
        };
        if (serviceUUIDs != null && serviceUUIDs.length > 0) {
            bluetoothLeScanner.startScan(filters, settings, scanCallback);
        } else {
            bluetoothLeScanner.startScan(null, settings, scanCallback);
        }

        if (scanSeconds > 0) {
            Handler handler = new Handler();
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    LOG.d(TAG, "Stopping Scan");
                    BLECentralPlugin.this.bluetoothLeScanner.stopScan(scanCallback);
                }
            }, scanSeconds * 1000);
        }

        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
        result.setKeepCallback(true);
        callbackContext.sendPluginResult(result);
    }

    private void listKnownDevices(CallbackContext callbackContext) {

        JSONArray json = new JSONArray();

        // do we care about consistent order? will peripherals.values() be in order?
        for (Map.Entry<String, Peripheral> entry : peripherals.entrySet()) {
            Peripheral peripheral = entry.getValue();
            if (!peripheral.isUnscanned()) {
                json.put(peripheral.asJSONObject());
            }
        }

        PluginResult result = new PluginResult(PluginResult.Status.OK, json);
        callbackContext.sendPluginResult(result);
    }

    @Override
    public void onLeScan(BluetoothDevice device, int rssi, byte[] scanRecord) {
        onLeDeviceScanned(device, rssi, scanRecord);
    }

    private void onLeDeviceScanned(BluetoothDevice device, int rssi, byte[] scanRecord){
        String address = device.getAddress();
        boolean alreadyReported = peripherals.containsKey(address) && !peripherals.get(address).isUnscanned();

        if (!alreadyReported) {

            Peripheral peripheral = new Peripheral(device, rssi, scanRecord);
            peripherals.put(device.getAddress(), peripheral);

            if (discoverCallback != null) {
                PluginResult result = new PluginResult(PluginResult.Status.OK, peripheral.asJSONObject());
                result.setKeepCallback(true);
                discoverCallback.sendPluginResult(result);
            }

        } else {
            Peripheral peripheral = peripherals.get(address);
            peripheral.update(rssi, scanRecord);
            if (reportDuplicates && discoverCallback != null) {
                PluginResult result = new PluginResult(PluginResult.Status.OK, peripheral.asJSONObject());
                result.setKeepCallback(true);
                discoverCallback.sendPluginResult(result);
            }
        }
    }

    public HashMap<String, Object> parseAdvertisementPacket(final byte[] scanRecord) {
        byte[] advertisedData = Arrays.copyOf(scanRecord, scanRecord.length);
        List<UUID> uuids = new ArrayList<>();
        byte[] MfgData = null;
        byte[] serviceData = null;
        int i;

        int offset = 0;
        while (offset < (advertisedData.length - 2)) {
            int len = advertisedData[offset++];
            if (len == 0)
                break;

            int type = advertisedData[offset++];
            switch (type & 0xFF) {
                case 0x02: // Partial list of 16-bit UUIDs
                case 0x03: // Complete list of 16-bit UUIDs
                    while (len > 1) {
                        int uuid16 = advertisedData[offset++] & 0xFF;
                        uuid16 |= (advertisedData[offset++] << 8);
                        len -= 2;
                        uuids.add(UUID.fromString(String.format(
                                "%08x-0000-1000-8000-00805f9b34fb", uuid16)));
                    }
                    break;
                case 0x06:// Partial list of 128-bit UUIDs
                case 0x07:// Complete list of 128-bit UUIDs
                    // Loop through the advertised 128-bit UUID's.
                    while (len >= 16) {
                        try {
                            // Wrap the advertised bits and order them.
                            ByteBuffer buffer = ByteBuffer.wrap(advertisedData,
                                    offset++, 16).order(ByteOrder.LITTLE_ENDIAN);
                            long mostSignificantBit = buffer.getLong();
                            long leastSignificantBit = buffer.getLong();
                            uuids.add(new UUID(leastSignificantBit,
                                    mostSignificantBit));
                        } catch (IndexOutOfBoundsException e) {
                            // Defensive programming.
                            Log.e("BleDeviceF.parseUUID", e.toString());
                        } finally {
                            // Move the offset to read the next uuid.
                            offset += 15;
                            len -= 16;
                        }
                    }
                    break;
                case 0xFF:  // Manufacturer Specific Data
                    MfgData = new byte[len];
                    i = 0;
                    while (len > 1) {
                        if (i < 32) {
                            MfgData[i++] = advertisedData[offset++];
                        }
                        len -= 1;
                    }
                    break;
                case 0x16: // Service Data
                    serviceData = new byte[len];
                    i = 0;
                    offset += 2;
                    while(len - 2 > 1){
                        serviceData[i++] = advertisedData[offset++];
                        len -= 1;
                    }

                    break;
                default:
                    offset += (len - 1);
                    break;
            }
        }
        HashMap<String, Object> result = new HashMap<>();
        result.put("UUIDs", uuids);
        if(MfgData != null) {
            result.put("ManufacturerData", MfgData);
        }
        if(serviceData != null) {
            int bitInteger = serviceData[0];
            result.put("ServiceData", bitInteger == 1);
        }
        return result;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {

        if (requestCode == REQUEST_ENABLE_BLUETOOTH) {

            if (resultCode == Activity.RESULT_OK) {
                LOG.d(TAG, "User enabled Bluetooth");
                if (enableBluetoothCallback != null) {
                    enableBluetoothCallback.success();
                }
            } else {
                LOG.d(TAG, "User did *NOT* enable Bluetooth");
                if (enableBluetoothCallback != null) {
                    enableBluetoothCallback.error("User did not enable Bluetooth");
                }
            }

            enableBluetoothCallback = null;
        }
    }

    /* @Override */
    public void onRequestPermissionResult(int requestCode, String[] permissions,
                                          int[] grantResults) /* throws JSONException */ {
        for(int result:grantResults) {
            if(result == PackageManager.PERMISSION_DENIED)
            {
                LOG.d(TAG, "User *rejected* Coarse Location Access");
                this.permissionCallback.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, PERMISSION_DENIED_ERROR));
                return;
            }
        }

        switch(requestCode) {
            case REQUEST_ACCESS_COARSE_LOCATION:
                LOG.d(TAG, "User granted Coarse Location Access");
                findLowEnergyDevices(permissionCallback, serviceUUIDs, scanSeconds);
                this.permissionCallback = null;
                this.serviceUUIDs = null;
                this.scanSeconds = -1;
                break;
        }
    }

    private UUID uuidFromString(String uuid) {
        return UUIDHelper.uuidFromString(uuid);
    }

    /**
     * Reset the BLE scanning options
     */
    private void resetScanOptions() {
        this.reportDuplicates = false;
    }

    private void upgradeFirmware(final CallbackContext callbackContext, String macAddress, final Uri uri) {

        final Peripheral peripheral = peripherals.get(macAddress);

        if (peripheral == null) {
            callbackContext.error("Peripheral " + macAddress + " not found.");
            return;
        }

        if (!peripheral.isConnected()) {
            callbackContext.error("Peripheral " + macAddress + " is not connected.");
            return;
        }

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                peripheral.upgradeFirmware(callbackContext, uri);
            }
        });
    }

}

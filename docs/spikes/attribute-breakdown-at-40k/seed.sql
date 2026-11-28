-- psql variables: n is the fleet size, tenant is the synthetic operational tenant.
INSERT INTO tenants(id,slug,name,kind,created_at,updated_at)
VALUES (:'tenant','bench','Synthetic fleet','operational',now(),now());
SELECT set_config('looninspect.tenant_id', :'tenant', false);
INSERT INTO mdm_connections(id,tenant_id,name,provider,base_url,is_active,patch_management_provider,
  loonsecio_data_sharing_enabled,capability_devices,capability_users,capability_webhooks,capability_jamf_pro,created_at,updated_at)
VALUES (1,:'tenant','Synthetic Jamf','jamf','https://mdm.example.invalid',true,'none',false,true,false,false,false,now(),now());
INSERT INTO devices(id,tenant_id,mdm_connection_id,mdm_provider,external_id,serial_number,hostname,managed,supervised,os_version,site,building_id)
SELECT i,:'tenant',1,'jamf',i::text,'FIXTURE-'||i,'mac-'||i,(i%5<>0),(i%7<>0),'26.'||(i%5),
  CASE WHEN i%3=0 THEN 'South' ELSE 'North' END,(i%8)::text FROM generate_series(1,:n) i;
INSERT INTO device_extension_attributes(tenant_id,device_id,definition_id,name,"values",source,enabled)
SELECT :'tenant',i,j::text,'Attribute '||j,CASE WHEN i%50=1 THEN '[]'::jsonb ELSE jsonb_build_array('value-'||((i+j)%13)) END,
  'extensionAttributes',true FROM generate_series(1,:n) i CROSS JOIN generate_series(1,150) j
ORDER BY i,j; -- The inventory collector writes a device's definitions together.

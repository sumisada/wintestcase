# coding: utf-8

require 'spec_helper'

describe "☆OS情報☆" do
  describe " OS名" do
    describe command('systeminfo') do
      its(:stdout) { should contain('Microsoft Windows Server 2019 Standard') }
      # its(:stdout) { should contain('10.0.17763 N/A ビルド17763') }
    end
    describe command('cmd') do
      its(:stdout) { should contain('Version 10.0.17763.2114') }
    end
    describe windows_registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion') do
      it { should exist }
      it { should have_property_value('CurrentBuild', :type_string, '17763') }
      it { should have_property_value('ReleaseId',:type_sz, '1809') }
    end
    # SMB通信暗号化常時）
    describe windows_registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters') do
      it { should exist }
      it { should have_property_value('RequireSecuritySignature', :type_dword, '1') }
    end

    # Cipher suite
    describe "Cipher Suite" do
      describe windows_registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002') do
        it { should exist }
        it { should have_property_value('Functions',:type_multistring,'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CCM,TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CCM,TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_CCM,TLS_DHE_RSA_WITH_AES_128_CCM_8,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_CCM,TLS_DHE_RSA_WITH_AES_256_CCM_8,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256' ) }
      end
    end
    
    # RDPセッション複数化 fSingleSessionPerUser, fSingleSessionPerUser
    # 効果なし
    describe windows_registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server') do
      it { should exist }
      it { should have_property_value('fSingleSessionPerUser', :type_dword, '1') }
    end
    # 効果あり
    describe windows_registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
      it { should exist }
      it { should have_property_value('fSingleSessionPerUser', :type_dword, '0') }
    end

    #　画面ロック
    describe windows_registry_key('HKEY_CURRENT_USER\Control Panel\Desktop') do
      it { should exist }
      it { should have_property_value('ScreenSaveActive', :type_sz, '1') }
    end
    describe windows_registry_key('HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop') do
      it { should exist }
      it { should have_property_value('ScreenSaveActive', :type_string, '1') }
      it { should have_property_value('ScreenSaveTimeOut', :type_string, '600') }
      it { should have_property_value('ScreenSaverIsSecure', :type_string, '1') }
    end

  end

  describe "2.2-2 デフラグ最適化スケジュール(OFF)" do
    describe command('schtasks /query /TN \Microsoft\Windows\Defrag\ScheduledDefrag') do
      its(:stdout) { should contain('無効') }
    end
  end

  describe "SNMP" do
    describe service('SNMP') do
      it { should be_enabled }
    end
  end


  describe "Firewall" do
    describe command('netsh advfirewall show domainprofile') do
      its(:stdout) { should match "State                                 オン" }
    end
    describe command('netsh advfirewall show privateprofile') do
      its(:stdout) { should match "State                                 オフ" }
    end
    describe command('netsh advfirewall show publicprofile') do
      its(:stdout) { should match "State                                 オン" }
    end
  end
  
  describe "TEST WinRM" do
    describe windows_registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation') do
      it { should exist }
      #it { should have_property('RealTimeIsUniversal') }
      it { should have_property_value('TimeZoneKeyName', :type_string, 'Tokyo Standard Time') }
    end
  end
end

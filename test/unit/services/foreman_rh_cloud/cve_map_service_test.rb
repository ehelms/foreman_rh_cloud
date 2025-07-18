require 'test_plugin_helper'

class ForemanRhCloud::CveMapServiceTest < ActiveSupport::TestCase
  setup do
    @service = ForemanRhCloud::CveMapService
    @xml_content = '<?xml version="1.0"?><cve_map><test>content</test></cve_map>'

    Rails.cache.clear
  end

  test 'should return local file content when file exists' do
    File.stubs(:exist?).with(@service::LOCAL_FILE_PATH).returns(true)
    File.stubs(:read).with(@service::LOCAL_FILE_PATH).returns(@xml_content)

    result = @service.get_cve_map_content

    assert_equal @xml_content, result
  end

  test 'should return cached content when available' do
    File.stubs(:exist?).with(@service::LOCAL_FILE_PATH).returns(false)
    Rails.cache.write(@service::CACHE_KEY, @xml_content)

    result = @service.get_cve_map_content

    assert_equal @xml_content, result
  end

  test 'should download and cache content when no local file or cache' do
    File.stubs(:exist?).with(@service::LOCAL_FILE_PATH).returns(false)

    response = mock('response')
    response.stubs(:code).returns('200')
    response.stubs(:body).returns(@xml_content)

    http = mock('http')
    http.stubs(:use_ssl=)
    http.stubs(:verify_mode=)
    http.stubs(:request).returns(response)

    Net::HTTP.stubs(:new).returns(http)

    result = @service.get_cve_map_content

    assert_equal @xml_content, result
    assert_equal @xml_content, Rails.cache.read(@service::CACHE_KEY)
  end

  test 'should handle download errors' do
    File.stubs(:exist?).with(@service::LOCAL_FILE_PATH).returns(false)

    response = mock('response')
    response.stubs(:code).returns('500')
    response.stubs(:message).returns('Internal Server Error')

    http = mock('http')
    http.stubs(:use_ssl=)
    http.stubs(:verify_mode=)
    http.stubs(:request).returns(response)

    Net::HTTP.stubs(:new).returns(http)

    assert_raises(StandardError) do
      @service.get_cve_map_content
    end
  end

  test 'should validate XML content' do
    File.stubs(:exist?).with(@service::LOCAL_FILE_PATH).returns(false)

    response = mock('response')
    response.stubs(:code).returns('200')
    response.stubs(:body).returns('invalid xml content')

    http = mock('http')
    http.stubs(:use_ssl=)
    http.stubs(:verify_mode=)
    http.stubs(:request).returns(response)

    Net::HTTP.stubs(:new).returns(http)

    assert_raises(StandardError) do
      @service.get_cve_map_content
    end
  end
end

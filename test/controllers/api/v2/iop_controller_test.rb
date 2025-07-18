require 'test_plugin_helper'

module Api
  module V2
    class IopControllerTest < ActionController::TestCase
      setup do
        @controller = Api::V2::IopController.new
        @request.env['HTTP_ACCEPT'] = 'application/json'
      end

      test 'should get cvemap successfully' do
        xml_content = '<?xml version="1.0"?><cve_map><test>content</test></cve_map>'

        ForemanRhCloud::CveMapService.stubs(:get_cve_map_content).returns(xml_content)

        get :cvemap

        assert_response :success
        assert_equal 'application/xml', response.content_type
        assert_equal xml_content, response.body
      end

      test 'should handle service errors gracefully' do
        ForemanRhCloud::CveMapService.stubs(:get_cve_map_content).raises(StandardError.new('Network error'))

        get :cvemap

        assert_response :internal_server_error
        response_json = JSON.parse(response.body)
        assert_equal 'Failed to retrieve CVE map', response_json['error']
        assert_equal 'Network error', response_json['message']
      end
    end
  end
end

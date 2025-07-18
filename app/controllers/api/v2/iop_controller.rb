module Api
  module V2
    class IopController < ::Api::V2::BaseController
      include ::Api::Version2

      api :GET, "/iop/meta/v1/cvemap.xml", N_("Get CVE map XML")
      def cvemap
        content = ForemanRhCloud::CveMapService.get_cve_map_content

        send_data content,
          type: 'application/xml',
          disposition: 'inline',
          filename: 'cvemap.xml'
      rescue StandardError => e
        Rails.logger.error "CVE map endpoint error: #{e.message}"
        render json: {
          error: 'Failed to retrieve CVE map',
          message: e.message,
        }, status: :internal_server_error
      end

      private

      def log_response_body
        # Skip logging response body for CVE map to avoid cluttering logs
        logger.debug { "Body: [CVE map content - logging skipped]" }
      end
    end
  end
end

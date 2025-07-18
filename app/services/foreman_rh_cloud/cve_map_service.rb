require 'net/http'
require 'openssl'
require 'rexml/document'

module ForemanRhCloud
  class CveMapService
    CVE_MAP_URL = 'https://security.access.redhat.com/data/meta/v1/cvemap.xml'.freeze
    LOCAL_FILE_PATH = '/var/lib/foreman/cvemap.xml'.freeze
    CACHE_KEY = 'cvemap_xml_content'.freeze
    CACHE_DURATION = 24.hours

    class << self
      def get_cve_map_content
        if File.exist?(LOCAL_FILE_PATH)
          Rails.logger.info "Using manual CVE map file from #{LOCAL_FILE_PATH}"
          return File.read(LOCAL_FILE_PATH)
        end

        cached_content = Rails.cache.read(CACHE_KEY)
        if cached_content.present?
          Rails.logger.info "Using cached CVE map content"
          return cached_content
        end

        Rails.logger.info "Downloading CVE map from #{CVE_MAP_URL}"
        download_and_cache_content
      end

      private

      def download_and_cache_content
        response = download_from_url
        content = response.body

        validate_xml_content(content)

        Rails.cache.write(CACHE_KEY, content, expires_in: CACHE_DURATION)
        Rails.logger.info "CVE map downloaded and cached successfully"

        content
      rescue => e
        Rails.logger.error "Failed to download CVE map: #{e.message}"
        raise
      end

      def download_from_url
        uri = URI(CVE_MAP_URL)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER

        request = Net::HTTP::Get.new(uri)
        response = http.request(request)

        unless response.code == '200'
          raise "HTTP error #{response.code}: #{response.message}"
        end

        response
      end

      def validate_xml_content(content)
        return if content.blank?

        # Basic XML validation
        unless content.strip.start_with?('<?xml')
          raise "Invalid XML content: does not start with XML declaration"
        end

        # Try to parse to ensure it's valid XML
        begin
          REXML::Document.new(content)
        rescue REXML::ParseException => e
          raise "Invalid XML content: #{e.message}"
        end
      end
    end
  end
end

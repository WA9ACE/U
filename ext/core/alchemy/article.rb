module U::Core::Alchemy
  class Article
    attr_reader :url, :language, :text

    def initialize url, language, text
      @url = url
      @language = language
      @text = text
    end
  end
end

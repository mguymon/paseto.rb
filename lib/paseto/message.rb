module Paseto
  Message = Struct.new(:header, :payload, :footer) do
    def to_message
      message = [
        header,
        Paseto.encode64(payload)
      ]

      message << Paseto.encode64(footer) if footer

      message.join('.')
    end
  end
end
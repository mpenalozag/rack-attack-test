class MinimalController < ApplicationController
  def v1
    render json: { message: "hello world from v1" }
  end
end

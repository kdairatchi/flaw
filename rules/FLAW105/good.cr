class AdminController
  before_action :authenticate_admin!

  def destroy_all
    authorize! :manage, :all
    User.all.each(&.delete)
  end
end

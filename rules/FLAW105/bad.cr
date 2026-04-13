class AdminController
  # before_action :authenticate_admin!
  # authorize! :manage, :all

  def destroy_all
    User.all.each(&.delete)
  end
end

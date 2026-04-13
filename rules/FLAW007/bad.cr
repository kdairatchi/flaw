# FLAW007 — vulnerable: redirect target from query param
class PostsController
  def after_login(env)
    env.redirect(params["next"])
  end

  def returning(env)
    env.redirect("#{params["redirect_uri"]}")
  end

  def legacy(env)
    redirect_to params["url"]
  end
end

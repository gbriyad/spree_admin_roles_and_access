module Spree
  module Permissions
    def method_missing(name, *args, &block)
      if name.to_s.starts_with?('can')
        can, action, subject, attribute = find_action_and_subject(name)

        Permissions.send(:define_method, name) do |current_ability, user|
          if attribute.nil?
            current_ability.send(can, action, subject)
          else
            current_ability.send(can, action, subject, attribute)
          end
        end
        send(name, args[0], args[1]) if self.respond_to?(name)
      else
        super
      end
    end

    define_method('default-permissions') do |current_ability, user|
      current_ability.can :read, Spree::Country
      current_ability.can :read, Spree::OptionType
      current_ability.can :read, Spree::OptionValue
      current_ability.can :create, Spree::Order
      current_ability.can :show, Spree::Order do |order, token|
        order.user == user || order.token && token == order.token
      end
      current_ability.can :update, Spree::Order do |order, token|
        !order.completed? && (order.user == user || order.token && token == order.token)
      end
      current_ability.can :manage, Spree::Address do |address|
        address.user == user
      end
      current_ability.can :create, Spree::Address do |_address|
        user.id.present?
      end
      current_ability.can :read, Spree::CreditCard, user_id: user.id
      current_ability.can :read, Spree::Product
      current_ability.can :read, Spree::ProductProperty
      current_ability.can :read, Spree::Property
      current_ability.can :create, Spree.user_class
      current_ability.can [:show, :update, :destroy], Spree.user_class, id: user.id
      current_ability.can :read, Spree::State
      current_ability.can :read, Spree::Taxon
      current_ability.can :read, Spree::Taxonomy
      current_ability.can :read, Spree::Variant
      current_ability.can :read, Spree::Zone
    end

    define_method('default-admin-permissions') do |current_ability, user|
      current_ability.can :admin, Spree::Store
    end

    define_method('can-update-spree/users') do |current_ability, user|
      current_ability.can :update, Spree.user_class
      # The permission of cannot update role_ids was given to user so that no one with this permission can change role of user.
      current_ability.cannot :update, Spree.user_class, :role_ids
    end

    define_method('can-create-spree/users') do |current_ability, user|
      current_ability.can :create, Spree.user_class
      current_ability.cannot :create, Spree.user_class, :role_ids
    end

    define_method('can-manage-spree/config') do |current_ability, user|
      current_ability.can :manage, Spree::Config
    end

    define_method('can-admin-spree/config') do |current_ability, user|
      current_ability.can :admin, Spree::Config
    end

    private
      def find_action_and_subject(name)
        can, action, subject, attribute = name.to_s.split('-')

        if subject == 'all'
          return can.to_sym, action.to_sym, subject.to_sym, attribute.try(:to_sym)
        elsif (subject_class = subject.classify.safe_constantize) && subject_class.respond_to?(:ancestors)
          return can.to_sym, action.to_sym, subject_class, attribute.try(:to_sym)
        else
          return can.to_sym, action.to_sym, subject, attribute.try(:to_sym)
        end
      end
  end
end

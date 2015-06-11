class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
         
         
  before_save { email.downcase! }
  validates :name, presence: true, length: { maximum: 50 }
  
  validates :email, presence:   true
                    
  
 # validates :password_confirmation, presence: true
  attr_accessor :password, :password_confirmation
  
end

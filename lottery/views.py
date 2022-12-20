# IMPORTS
# IMPORTS

from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user

from app import db, requires_roles, decrypt_draws
from models import Draw

# CONFIG
lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@login_required
@requires_roles('user')
def lottery():
    return render_template('lottery/lottery.html')


@lottery_blueprint.route('/add_draw', methods=['POST'])
@login_required
@requires_roles('user')
def add_draw():
    submitted_draw = ''
    for i in range(6):
        input_draw = request.form.get('no' + str(i + 1))
        # If one of the values is blank, flash a message and set the boolean to false.
        if input_draw == '':
            flash('do not leave any values blank.')
        else:
            # If the value isn't blank, check if it's within allowed range.
            if int(input_draw) > 60 or int(input_draw) < 1:
                flash('Draw values must be between 1 and 60.')
            else:
                submitted_draw += input_draw + ' '

    # create a new draw with the form data.
    new_draw = Draw(user_id=current_user.id, numbers=submitted_draw, master_draw=False,
                    lottery_round=0)

    # add the new draw to the database
    db.session.add(new_draw)
    db.session.commit()

    # re-render lottery.page
    flash('Draw %s submitted.' % submitted_draw)
    return lottery()


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@login_required
@requires_roles('user')
def view_draws():
    # get all draws that have not been played [played=0]
    playable_draws = Draw.query.filter_by(been_played=False, user_id=current_user.id).all()

    # if playable draws exist
    if len(playable_draws) != 0:
        # re-render lottery page with playable draws
        return render_template('lottery/lottery.html', playable_draws=decrypt_draws(playable_draws))
    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@login_required
@requires_roles('user')
def check_draws():
    # get played draws
    played_draws = Draw.query.filter_by(played=True, user_id=current_user.id).all()

    # if played draws exist
    if len(played_draws) != 0:
        return render_template('lottery/lottery.html', results=decrypt_draws(played_draws), played=True)


    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# Delete all played draws.
@lottery_blueprint.route('/play_again', methods=['POST'])
@login_required
@requires_roles('user')
def play_again():
    delete_played = Draw.query.filter_by(played=True, user_id=current_user.id).all()
    for draw in delete_played:
        db.session.delete(draw)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()

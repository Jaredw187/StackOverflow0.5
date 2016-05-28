
console.log('MADE IT HERE');
$(window).on('load', function() {
    console.log('The page is loaded');
});

$('.widget.thumbsdown').on('click', function(){
    console.log('Thumbs Down was clicked.');
    var state = $(this).attr('data-state');
    var checked = state === 'checked';
    var nextState = checked ? 'unchecked' : 'checked';
    var elt = $(this);


    $.ajax('/update-dat-thumbs-down', {
        method: 'POST',
        data: {
            answer_id: $('.answer.id').attr('data-answer-id'),
            question_id: $('.answer.id').attr('data-question-id'),
            want_vote: !checked,
            _csrf_token: csrfToken
        },
        success: function (data) {
            /* called when post succeeds */
            console.log('post succeeded with result %s', data.result);
            elt.attr('data-state', nextState);
            location.reload(true);
        },
        error: function () {
            /* called when post fails */
            console.error('post failed');
            elt.attr('data-state', state);
            location.reload(true);
        }
    });
});


$('.widget.thumbsup').on('click', function(){
    console.log('Thumbs Up was clicked.');
    var state = $(this).attr('data-state');
    var checked = state === 'checked';
    var nextState = checked ? 'unchecked' : 'checked';
    var elt = $(this);

    $.ajax('/update-dat-thumbs-up', {
        method: 'POST',
        data: {
            answer_id: $('.answer.id').attr('data-answer-id'),
            question_id: $('.answer.id').attr('data-question-id'),
            want_vote: !checked,
            _csrf_token: csrfToken
        },
        success: function (data) {
            /* called when post succeeds */
            console.log('post succeeded with result %s', data.result);
            elt.attr('data-state', nextState);
            location.reload(true);
        },
        error: function () {
            /* called when post fails */
            console.error('post failed');
            elt.attr('data-state', state);
            location.reload(true);
        }
    });

});









